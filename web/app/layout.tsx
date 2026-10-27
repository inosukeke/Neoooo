import type { Metadata } from "next";
import { Inter, JetBrains_Mono } from "next/font/google";
import "./globals.css";

const inter = Inter({
  variable: "--font-inter",
  subsets: ["latin", "vietnamese"],
});

const jetbrainsMono = JetBrains_Mono({
  variable: "--font-jetbrains-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "Đồ thị tri thức an ninh — Demo",
  description: "Demo lab: Text2Cypher + GraphRAG trên đồ thị tri thức an ninh (dữ liệu mô phỏng).",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="vi" className={`${inter.variable} ${jetbrainsMono.variable} h-full`}>
      <body className="h-full antialiased">{children}</body>
    </html>
  );
}
