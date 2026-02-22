"""Lateral Movement Agent — Gemini-driven attack chain reasoning.

Gemini reasons over confirmed findings and the full asset graph, calling tools
(up to MAX_TOOL_ROUNDS per finding) to build concrete attack chains.
"""

import asyncio
import json
import logging
import re
import uuid
from datetime import datetime, timezone
from pydantic import BaseModel, ValidationError

from src.config import get_settings
from src.models.attack_chain import AttackChain, PivotStep, SensitiveStore
from src.models.finding import FindingDocument, LateralAgentInput
from src.agents.lateral.tools import (
    check_network_reachability,
    enumerate_credentials,
    check_iam_permissions,
    identify_sensitive_stores,
)

logger = logging.getLogger(__name__)


def _normalize_score(raw) -> float:
    """Clamp score to [0, 1]. If Gemini returns a 0-10 value, divide by 10."""
    v = float(raw)
    return min(1.0, max(0.0, v / 10.0 if v > 1.0 else v))


class _LLMFinalPivotStep(BaseModel):
    step: int
    asset: str
    action: str
    detail: str
    mitre: str | None = None


class _LLMFinalSensitiveStore(BaseModel):
    type: str
    asset: str
    contents: str
    credentials_used: str


class _LLMFinalAttackChain(BaseModel):
    entry_point: str
    pivot_path: list[_LLMFinalPivotStep]
    reachable_sensitive_stores: list[_LLMFinalSensitiveStore] = []
    blast_radius_score: float = 0.0
    blast_radius_summary: str
    gemini_reasoning: str
    mitre_techniques: list[str] = []


MAX_TOOL_ROUNDS = 8
MODEL_NAME = "gemini-2.5-flash"
LOG_SNIPPET_CHARS = 1200
_MITRE_ID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")

_SYSTEM_PROMPT = """You are a senior red team operator reasoning about lateral movement after an initial exploit.

Your job is to build a complete attack chain from a confirmed vulnerability. Think like an attacker: pivot through the network, extract credentials, escalate cloud permissions, identify sensitive data stores. Assess blast radius — what is the worst case if this chain is fully exploited?

STEP 1 — BEFORE CALLING ANY TOOLS:
Read the full finding and every asset in the asset graph. Identify all pivot paths worth investigating, ranked by potential blast radius. State your prioritized plan explicitly in your response before issuing the first tool call.

STEP 2 — TOOL CALLING STRATEGY:
1. Start with check_network_reachability to map what the entry asset can reach.
2. For credential_exposure or any finding with credentials_found, call enumerate_credentials.
3. If AWS credentials appear (type containing "aws"), call check_iam_permissions.
4. Call identify_sensitive_stores on the entry host and each reachable asset.
5. Stop when you have enough for a complete chain — do not exhaust 8 rounds needlessly.

FINAL OUTPUT:
When you have enough information, output ONLY raw JSON (no markdown fences, no prose before or after):
{
  "entry_point": "<url or ip:port of first compromised asset>",
  "pivot_path": [
    {"step": 1, "asset": "<hostname/ip>", "action": "<attacker action>", "detail": "<technical detail>", "mitre": "<Txxxx or null>"}
  ],
  "reachable_sensitive_stores": [
    {"type": "<database|secret|s3_bucket|docker>", "asset": "<host>", "contents": "<what is exposed>", "credentials_used": "<which creds>"}
  ],
  "blast_radius_score": 0.0,
  "blast_radius_summary": "<1-2 sentence plain English exec-readable summary>",
  "gemini_reasoning": "<your full step-by-step red team reasoning>",
  "mitre_techniques": ["T1552.001"]
}
Important: "credentials_used" must always be a string; if unknown, set it to "unknown" (never null)."""


def _sanitize_claim_language(text: str) -> str:
    """Tone down overclaims unless privilege depth is explicitly proven."""
    if not text:
        return text

    replacements = [
        (r"\bfull access\b", "authenticated access"),
        (r"\bfully compromised\b", "compromised"),
        (r"\bfull compromise\b", "compromise"),
    ]
    out = text
    for pattern, replacement in replacements:
        out = re.sub(pattern, replacement, out, flags=re.IGNORECASE)
    return out


# TODO: Make this more robust — currently just looks for keywords in the step text, but could be more systematic about mapping to MITRE techniques based on the specific finding type, assets involved, and evidence details.
def _infer_mitre_for_step(step: PivotStep) -> str | None:
    """Infer a missing MITRE technique from step action/detail text."""
    text = f"{step.action} {step.detail}".lower()

    if any(token in text for token in ["credential exposure", ".env", "db_password", "password", "secret"]):
        return "T1552.001"
    if any(token in text for token in ["connect to mysql", "database access", "using credentials", "valid account", "login"]):
        return "T1078"
    if any(token in text for token in ["data access", "s3", "database dump", "sensitive data"]):
        return "T1530"
    return None


def _normalize_mitre_techniques(
    pivot_path: list[PivotStep],
    mitre_techniques: list[str],
    reachable_sensitive_stores: list[SensitiveStore],
) -> list[str]:
    """
    Ensure MITRE techniques are complete and consistent with pivot steps/stores.
    """
    ordered: list[str] = []

    def _add(value: str | None) -> None:
        if not value:
            return
        if not _MITRE_ID_RE.match(value):
            return
        if value not in ordered:
            ordered.append(value)

    # Respect explicit per-step MITRE, but backfill missing values where obvious.
    for step in pivot_path:
        if not step.mitre:
            step.mitre = _infer_mitre_for_step(step)
        _add(step.mitre)

    # Include model-provided top-level techniques too.
    for tech in mitre_techniques:
        _add(tech)

    # If sensitive stores are reached, data access is in scope.
    if reachable_sensitive_stores:
        _add("T1530")

    return ordered


def _build_tool_declarations():
    """Build Gemini function declarations for the four lateral movement tools."""
    from google.genai import types

    return types.Tool(function_declarations=[
        types.FunctionDeclaration(
            name="check_network_reachability",
            description=(
                "TCP-probe a target host to determine which ports are open and "
                "whether lateral movement is feasible from the entry point."
            ),
            parameters=types.Schema(
                type=types.Type.OBJECT,
                properties={
                    "from_asset": types.Schema(
                        type=types.Type.STRING,
                        description="Source asset identifier (IP or URL of entry point).",
                    ),
                    "to_asset": types.Schema(
                        type=types.Type.STRING,
                        description="Target hostname or IP to probe.",
                    ),
                },
                required=["from_asset", "to_asset"],
            ),
        ),
        types.FunctionDeclaration(
            name="enumerate_credentials",
            description=(
                "Parse and verify credentials from the finding evidence. "
                "For credential_exposure, attempts live DB/AWS connections. "
                "For sql_injection, returns a structured stub."
            ),
            parameters=types.Schema(
                type=types.Type.OBJECT,
                properties={
                    "host": types.Schema(
                        type=types.Type.STRING,
                        description="Target host the finding is associated with.",
                    ),
                    "finding_id": types.Schema(
                        type=types.Type.STRING,
                        description="The finding_id of the current finding.",
                    ),
                },
                required=["host", "finding_id"],
            ),
        ),
        types.FunctionDeclaration(
            name="check_iam_permissions",
            description=(
                "Use boto3 to enumerate what permissions the leaked AWS credentials "
                "grant. Checks STS identity, S3 buckets, Secrets Manager, IAM user, "
                "and EC2 instances independently."
            ),
            parameters=types.Schema(
                type=types.Type.OBJECT,
                properties={
                    "service": types.Schema(
                        type=types.Type.STRING,
                        description="AWS region hint (e.g. 'us-east-1') or service name.",
                    ),
                    "finding_id": types.Schema(
                        type=types.Type.STRING,
                        description="The finding_id of the current finding.",
                    ),
                },
                required=["service", "finding_id"],
            ),
        ),
        types.FunctionDeclaration(
            name="identify_sensitive_stores",
            description=(
                "Port-scan for database services (MySQL, Postgres, MongoDB, Redis, "
                "Elasticsearch, Docker API) and HTTP-probe known admin interfaces "
                "(/phpmyadmin, /_cat/indices, etc.) on the target and reachable hosts."
            ),
            parameters=types.Schema(
                type=types.Type.OBJECT,
                properties={
                    "host": types.Schema(
                        type=types.Type.STRING,
                        description="Primary target host.",
                    ),
                    "reachable_assets": types.Schema(
                        type=types.Type.ARRAY,
                        items=types.Schema(type=types.Type.STRING),
                        description="Additional hosts found reachable from the entry point.",
                    ),
                    "finding_id": types.Schema(
                        type=types.Type.STRING,
                        description="The finding_id of the current finding.",
                    ),
                },
                required=["host", "reachable_assets", "finding_id"],
            ),
        ),
    ])


class LateralAgent:
    """
    Fully agentic lateral movement agent.

    Gemini reasons across confirmed findings + the full asset graph and
    decides pivot paths via tool calls (up to MAX_TOOL_ROUNDS per finding).
    """

    def __init__(self, api_key: str | None = None, verbose_llm: bool = False):
        self.api_key = api_key or get_settings().GEMINI_API_KEY
        self.verbose_llm = verbose_llm
        if not self.api_key:
            raise ValueError("GEMINI_API_KEY not set")

        try:
            from google import genai
        except ImportError as exc:
            raise ImportError(
                "google-genai is required. Install with: pip install google-genai"
            ) from exc

        self.client = genai.Client(api_key=self.api_key)

    @staticmethod
    def _truncate_for_log(value, limit: int = LOG_SNIPPET_CHARS) -> str:
        text = value if isinstance(value, str) else json.dumps(value, default=str)
        if len(text) <= limit:
            return text
        return text[:limit] + f"... [truncated {len(text) - limit} chars]"

    def _log_model_parts(self, finding_id: str, round_num: int, model_content) -> None:
        """Emit raw model text/tool-call parts for debugging."""
        if not self.verbose_llm:
            return

        for idx, part in enumerate(model_content.parts):
            if getattr(part, "function_call", None):
                fc = part.function_call
                logger.debug(
                    "LLM[%s] round=%d part=%d function_call=%s args=%s",
                    finding_id,
                    round_num + 1,
                    idx,
                    fc.name,
                    self._truncate_for_log(dict(fc.args)),
                )
            elif hasattr(part, "text") and part.text:
                logger.debug(
                    "LLM[%s] round=%d part=%d text=%s",
                    finding_id,
                    round_num + 1,
                    idx,
                    self._truncate_for_log(part.text),
                )

    async def run(self, input: LateralAgentInput) -> list[AttackChain]:
        """
        Process all confirmed findings and produce attack chain documents.

        Args:
            input: LateralAgentInput with findings (multi_asset, exploitable)
                   and the full asset graph for this engagement.

        Returns:
            List of AttackChain documents, one per successfully reasoned finding.
        """
        # Build registry once: finding_id -> serialized dict for tool injection
        registry: dict[str, dict] = {
            f.finding_id: f.model_dump(mode="json")
            for f in input.findings
        }

        chains: list[AttackChain] = []
        for finding in input.findings:
            logger.info(
                f"Processing finding {finding.finding_id} "
                f"({finding.vulnerability_class}, severity={finding.severity})"
            )
            chain = await self._process_finding(finding, input.asset_graph, registry)
            if chain is not None:
                chains.append(chain)

        logger.info(f"LateralAgent complete: {len(chains)} attack chains built")
        return chains

    async def _process_finding(
        self,
        finding: FindingDocument,
        asset_graph,
        registry: dict[str, dict],
    ) -> AttackChain | None:
        """Run the Gemini tool-calling loop for a single finding."""
        from google.genai import types

        tool_declarations = _build_tool_declarations()
        config = types.GenerateContentConfig(
            system_instruction=_SYSTEM_PROMPT,
            tools=[tool_declarations],
            temperature=0.1,
        )

        initial_message = (
            f"Confirmed finding to investigate:\n"
            f"{finding.model_dump_json(indent=2)}\n\n"
            f"Full asset graph ({len(asset_graph)} assets):\n"
            f"{json.dumps([a.model_dump(mode='json') for a in asset_graph], indent=2)}"
        )

        contents = [
            types.Content(
                role="user",
                parts=[types.Part.from_text(text=initial_message)],
            )
        ]

        for round_num in range(MAX_TOOL_ROUNDS):
            response = None
            for attempt in range(3):
                try:
                    response = await self.client.aio.models.generate_content(
                        model=MODEL_NAME,
                        contents=contents,
                        config=config,
                    )
                    break
                except Exception as e:
                    is_rate_limit = "429" in str(e) or "RESOURCE_EXHAUSTED" in str(e)
                    if is_rate_limit and attempt < 2:
                        wait = 30 * (attempt + 1)
                        logger.warning(
                            f"Rate limited on round {round_num} for "
                            f"{finding.finding_id}. Retrying in {wait}s "
                            f"(attempt {attempt + 1}/3)"
                        )
                        await asyncio.sleep(wait)
                    else:
                        logger.error(
                            f"Gemini API error on round {round_num} for "
                            f"{finding.finding_id}: {e}"
                        )
                        return None
            if response is None:
                return None

            model_content = response.candidates[0].content
            contents.append(model_content)
            self._log_model_parts(finding.finding_id, round_num, model_content)

            function_calls = [p for p in model_content.parts if p.function_call]

            if not function_calls:
                logger.info(
                    f"Finding {finding.finding_id}: Gemini finished after "
                    f"{round_num + 1} round(s)"
                )
                return await self._generate_structured_final_chain(contents, finding)

            # Execute all tool calls and collect responses
            fn_response_parts = []
            for fc_part in function_calls:
                result = await self._dispatch_tool_call(
                    fc_part.function_call, registry, asset_graph
                )
                if self.verbose_llm:
                    logger.debug(
                        "LLM[%s] tool_result=%s payload=%s",
                        finding.finding_id,
                        fc_part.function_call.name,
                        self._truncate_for_log(result),
                    )
                fn_response_parts.append(
                    types.Part(
                        function_response=types.FunctionResponse(
                            name=fc_part.function_call.name,
                            response={"result": result},
                        )
                    )
                )
                logger.debug(
                    f"Tool {fc_part.function_call.name} returned "
                    f"{len(str(result))} chars"
                )

            contents.append(types.Content(role="user", parts=fn_response_parts))

        # Reached MAX_TOOL_ROUNDS — ask for final output without tools
        logger.warning(
            f"Finding {finding.finding_id} hit MAX_TOOL_ROUNDS={MAX_TOOL_ROUNDS}. "
            "Requesting final summary."
        )
        return await self._generate_structured_final_chain(contents, finding)

    async def _generate_structured_final_chain(
        self,
        contents,
        finding: FindingDocument,
    ) -> AttackChain | None:
        """
        Request strict JSON schema output and perform one corrective retry if needed.
        """
        from google.genai import types

        config = types.GenerateContentConfig(
            system_instruction=_SYSTEM_PROMPT,
            temperature=0.1,
            response_mime_type="application/json",
            response_schema=_LLMFinalAttackChain,
        )

        local_contents = list(contents)
        last_error = ""
        for attempt in range(2):
            try:
                response = await self.client.aio.models.generate_content(
                    model=MODEL_NAME,
                    contents=local_contents,
                    config=config,
                )
            except Exception as e:
                logger.error(
                    "Structured final call failed for %s (attempt %d/2): %s",
                    finding.finding_id,
                    attempt + 1,
                    e,
                )
                return None

            parsed = getattr(response, "parsed", None)
            raw_text = getattr(response, "text", "") or ""
            if self.verbose_llm and raw_text:
                logger.debug(
                    "LLM[%s] structured_final_raw=%s",
                    finding.finding_id,
                    self._truncate_for_log(raw_text),
                )
            try:
                if parsed is None:
                    # Some SDK paths may not populate response.parsed; validate manually.
                    if not raw_text:
                        raise ValueError("Model returned empty structured response text")
                    data = _LLMFinalAttackChain.model_validate_json(raw_text)
                else:
                    data = _LLMFinalAttackChain.model_validate(parsed)
                return self._build_attack_chain_from_structured(data, finding)
            except (ValidationError, ValueError) as e:
                last_error = str(e)
                logger.warning(
                    "Structured output validation failed for %s (attempt %d/2): %s",
                    finding.finding_id,
                    attempt + 1,
                    e,
                )
                if attempt == 0:
                    repair_prompt = (
                        "Return the same final attack-chain JSON, but fix schema errors exactly. "
                        "Do not add prose. Ensure every reachable_sensitive_stores[].credentials_used "
                        "is a non-null string."
                    )
                    if raw_text:
                        repair_prompt += (
                            f"\nPrevious invalid JSON:\n{raw_text}\nValidation error:\n{last_error}"
                        )
                    local_contents.append(
                        types.Content(
                            role="user",
                            parts=[types.Part.from_text(text=repair_prompt)],
                        )
                    )

        logger.error(
            "Structured output failed after repair for %s: %s",
            finding.finding_id,
            last_error or "unknown validation error",
        )
        return None

    def _build_attack_chain_from_structured(
        self,
        data: _LLMFinalAttackChain,
        finding: FindingDocument,
    ) -> AttackChain:
        pivot_path = [PivotStep(**step.model_dump()) for step in data.pivot_path]
        stores = [SensitiveStore(**store.model_dump()) for store in data.reachable_sensitive_stores]
        for step in pivot_path:
            step.detail = _sanitize_claim_language(step.detail)
        for store in stores:
            store.contents = _sanitize_claim_language(store.contents)
        mitre_techniques = _normalize_mitre_techniques(
            pivot_path=pivot_path,
            mitre_techniques=data.mitre_techniques,
            reachable_sensitive_stores=stores,
        )
        return AttackChain(
            engagement_id=finding.engagement_id,
            chain_id=str(uuid.uuid4()),
            entry_point_finding_id=finding.finding_id,
            entry_point=data.entry_point,
            pivot_path=pivot_path,
            reachable_sensitive_stores=stores,
            blast_radius_score=_normalize_score(data.blast_radius_score),
            blast_radius_summary=_sanitize_claim_language(data.blast_radius_summary),
            gemini_reasoning=_sanitize_claim_language(data.gemini_reasoning),
            mitre_techniques=mitre_techniques,
            discovered_at=datetime.now(timezone.utc),
        )

    async def _dispatch_tool_call(
        self,
        function_call,
        registry: dict[str, dict],
        asset_graph,
    ) -> dict:
        """Route a Gemini function_call to the correct Python tool function."""
        name = function_call.name
        # function_call.args is a proto MapComposite — convert to plain dict
        args: dict = dict(function_call.args)

        # Inject finding from registry wherever finding_id is present
        if "finding_id" in args:
            finding_id = args.pop("finding_id")
            args["finding"] = registry.get(finding_id, {})

        # Proto repeated fields need explicit list conversion
        if "reachable_assets" in args:
            args["reachable_assets"] = list(args["reachable_assets"])

        dispatch_map = {
            "check_network_reachability": check_network_reachability,
            "enumerate_credentials": enumerate_credentials,
            "check_iam_permissions": check_iam_permissions,
            "identify_sensitive_stores": identify_sensitive_stores,
        }

        fn = dispatch_map.get(name)
        if fn is None:
            logger.warning(f"Unknown tool call: {name}")
            return {"error": f"Unknown tool: {name}"}

        try:
            return await fn(**args)
        except Exception as e:
            logger.error(f"Tool {name} raised: {e}")
            return {"error": str(e)}

    def _parse_attack_chain(
        self,
        raw_text: str,
        finding: FindingDocument,
    ) -> AttackChain | None:
        """Parse Gemini's final JSON response into an AttackChain model."""
        if not raw_text.strip():
            logger.error(f"Empty response for finding {finding.finding_id}")
            return None

        # Strip markdown code fences if Gemini wrapped the JSON anyway
        text = re.sub(r"```(?:json)?\s*|\s*```", "", raw_text).strip()

        try:
            data = json.loads(text)
        except json.JSONDecodeError as e:
            logger.error(
                f"JSON parse failed for {finding.finding_id}: {e}\n"
                f"Raw text (first 500 chars): {raw_text[:500]}"
            )
            return None

        try:
            pivot_path = [PivotStep(**step) for step in data.get("pivot_path", [])]
            stores = [
                SensitiveStore(**s)
                for s in data.get("reachable_sensitive_stores", [])
            ]
            for step in pivot_path:
                step.detail = _sanitize_claim_language(step.detail)
            for store in stores:
                store.contents = _sanitize_claim_language(store.contents)
            mitre_techniques = _normalize_mitre_techniques(
                pivot_path=pivot_path,
                mitre_techniques=data.get("mitre_techniques", []),
                reachable_sensitive_stores=stores,
            )
            return AttackChain(
                engagement_id=finding.engagement_id,
                chain_id=str(uuid.uuid4()),
                entry_point_finding_id=finding.finding_id,
                entry_point=data["entry_point"],
                pivot_path=pivot_path,
                reachable_sensitive_stores=stores,
                blast_radius_score=_normalize_score(data.get("blast_radius_score", 0.0)),
                blast_radius_summary=_sanitize_claim_language(
                    data.get("blast_radius_summary", "")
                ),
                gemini_reasoning=_sanitize_claim_language(
                    data.get("gemini_reasoning", "")
                ),
                mitre_techniques=mitre_techniques,
                discovered_at=datetime.now(timezone.utc),
            )
        except (KeyError, ValueError, TypeError) as e:
            logger.error(
                f"AttackChain construction failed for {finding.finding_id}: {e}\n"
                f"Parsed data keys: "
                f"{list(data.keys()) if isinstance(data, dict) else 'not a dict'}"
            )
            return None
