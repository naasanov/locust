export default function Home() {
  return (
    <main className="flex min-h-screen flex-col items-center justify-center gap-4 px-8">
      <h1 className="text-4xl font-bold tracking-tight text-zinc-100">artaas</h1>
      <p className="text-sm text-zinc-500">autonomous red team assessment platform</p>
      <div className="mt-8 h-96 w-full max-w-4xl rounded-lg border border-zinc-800 bg-zinc-900 flex items-center justify-center">
        <span className="text-zinc-600 text-sm">attack graph · d3 canvas</span>
      </div>
    </main>
  );
}
