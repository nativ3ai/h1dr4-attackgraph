import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Documentation // H1DR4 AttackGraph',
  description: 'Operator and developer documentation for H1DR4 AttackGraph, Sibyl Memory, telemetry, identity and H3RETIK execution.',
};

export default function DocsLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return children;
}
