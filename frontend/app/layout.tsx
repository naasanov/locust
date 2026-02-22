import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "LOCUST",
  description: "Autonomous red team assessment platform",
  icons: {
    icon: '/locust.png',
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <body className="antialiased">
        {children}
      </body>
    </html>
  );
}
