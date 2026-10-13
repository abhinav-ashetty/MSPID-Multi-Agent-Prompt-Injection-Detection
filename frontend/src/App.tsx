import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import { Dashboard } from './pages/Dashboard';
import { Analyze } from './pages/Analyze';
import { Assessments } from './pages/Assessments';
import { AssessmentDetails } from './pages/AssessmentDetails';
import { Simulation } from './pages/Simulation';
import { SimulationDetails } from './pages/SimulationDetails';
import { Navbar } from './components/layout/Navbar';

export default function App() {
  return <BrowserRouter><Navbar /><main className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
    <Routes>
      <Route path="/" element={<Navigate to="/dashboard" replace />} />
      <Route path="/dashboard" element={<Dashboard />} />
      <Route path="/analyze" element={<Analyze />} />
      <Route path="/assessments" element={<Assessments />} />
      <Route path="/assessments/:id" element={<AssessmentDetails />} />
      <Route path="/simulations" element={<Simulation />} />
      <Route path="/simulations/:simulationId" element={<SimulationDetails />} />
      <Route path="*" element={<p>Page not found.</p>} />
    </Routes>
  </main></BrowserRouter>;
}
