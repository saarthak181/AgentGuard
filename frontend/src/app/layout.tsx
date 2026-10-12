import type { Metadata } from "next";
import "./globals.css";
export const metadata:Metadata={title:"AgentGuard | Security console",description:"AI agent security and audit dashboard"};
export default function RootLayout({children}:{children:React.ReactNode}){return <html lang="en"><body>{children}</body></html>}
