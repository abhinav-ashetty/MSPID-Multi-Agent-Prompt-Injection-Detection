import type { ComponentType } from 'react';
interface Props { title: string; value: number | string; icon?: ComponentType<{ className?: string }>; variant?: 'blue' | 'green' | 'yellow' | 'red'; }
const colors = { blue: 'text-blue-600', green: 'text-green-600', yellow: 'text-yellow-600', red: 'text-red-600' };
export function StatCard({ title, value, icon: Icon, variant = 'blue' }: Props) {
  return <article className="rounded-xl border bg-white p-5 shadow-sm"><div className="flex items-center gap-3">{Icon && <Icon className={`h-5 w-5 ${colors[variant]}`} />}<h2 className="text-sm text-gray-600">{title}</h2></div><p className="mt-3 text-2xl font-bold">{value}</p></article>;
}
