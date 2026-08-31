import type { Metadata } from 'next';
import { Geist, Geist_Mono } from 'next/font/google';
import './globals.css';

const geistSans = Geist({ variable: '--font-geist-sans', subsets: ['latin'] });
const geistMono = Geist_Mono({ variable: '--font-geist-mono', subsets: ['latin'] });

export const metadata: Metadata = {
  metadataBase: new URL(process.env.NEXT_PUBLIC_SITE_URL || 'http://localhost:3000'),
  title: 'H1DR4 ATTACKGRAPH',
  description: 'Persistent operational memory for red-team agents.',
  openGraph: {
    title: 'H1DR4 ATTACKGRAPH',
    description: 'Persistent operational memory for red-team agents.',
    images: [{ url: '/og.png', width: 1200, height: 630, alt: 'H1DR4 ATTACKGRAPH' }],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'H1DR4 ATTACKGRAPH',
    description: 'Persistent operational memory for red-team agents.',
    images: ['/og.png'],
  },
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en"><body className={`${geistSans.variable} ${geistMono.variable}`}>{children}</body></html>;
}
