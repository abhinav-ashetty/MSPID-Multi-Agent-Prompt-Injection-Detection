import { Link, NavLink } from 'react-router-dom';
import { ShieldCheck } from 'lucide-react';
export function Navbar() {
  const cls = ({ isActive }: { isActive: boolean }) => `rounded px-3 py-2 text-sm ${isActive ? 'bg-blue-50 text-blue-700' : 'text-gray-700 hover:bg-gray-50'}`;
  return <header className="border-b bg-white"><div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-3 px-4 py-3 sm:px-6 lg:px-8"><Link to="/dashboard" className="flex items-center gap-2 font-semibold"><ShieldCheck className="h-6 w-6 text-blue-600"/>AIShield</Link><nav className="flex flex-wrap gap-1"><NavLink to="/dashboard" className={cls}>Dashboard</NavLink><NavLink to="/analyze" className={cls}>Analyze</NavLink><NavLink to="/assessments" className={cls}>Assessments</NavLink><NavLink to="/simulations" className={cls}>Simulations</NavLink></nav></div></header>;
}
