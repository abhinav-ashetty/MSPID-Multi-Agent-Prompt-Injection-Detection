import { useState, type FormEvent } from 'react';
import { Link } from 'react-router-dom';
import axios from 'axios';
import { securityApi } from '../services/api';
import type { SecurityAnalysisResponse } from '../types/security';

export function Analyze() {
  const [prompt, setPrompt] = useState('');
  const [result, setResult] = useState<SecurityAnalysisResponse | null>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [useGemini, setUseGemini] = useState(true);
  async function submit(event: FormEvent) {
    event.preventDefault(); setError(''); setResult(null);
    if (!prompt.trim()) { setError('Enter a prompt to analyze.'); return; }
    setLoading(true);
    try { setResult(await securityApi.analyzePrompt({ prompt, use_gemini: useGemini })); }
    catch (caught) {
      const detail = axios.isAxiosError<{ detail?: string }>(caught)
        ? caught.response?.data?.detail
        : undefined;
      setError(detail || 'Analysis failed. Confirm the backend is running and configured, then try again.');
    }
    finally { setLoading(false); }
  }
  return <section>
    <h1 className="mb-6 text-2xl font-bold">Analyze a prompt</h1>
    <form onSubmit={submit} className="rounded-xl border bg-white p-6 shadow-sm">
      <label htmlFor="prompt" className="mb-2 block font-medium">Prompt</label>
      <textarea id="prompt" value={prompt} onChange={e => setPrompt(e.target.value)} maxLength={10000} rows={6} className="w-full rounded border p-3" placeholder="Paste a prompt for security analysis" />
      <label className="mt-4 flex items-start gap-2 text-sm">
        <input
          type="checkbox"
          checked={useGemini}
          onChange={event => setUseGemini(event.target.checked)}
          disabled={loading}
          className="mt-0.5"
        />
        <span>
          <span className="block font-medium">Use Gemini</span>
          <span className="text-gray-600">
            {useGemini
              ? 'Includes Gemini analysis and uses your API quota.'
              : 'Off: analyze locally with rule-based and ML detectors only.'}
          </span>
        </span>
      </label>
      <div className="mt-3 flex items-center justify-between"><span className="text-sm text-gray-500">{prompt.length}/10000</span><button disabled={loading} className="rounded bg-blue-600 px-4 py-2 text-white disabled:opacity-50">{loading ? 'Analyzing…' : 'Analyze'}</button></div>
      {error && <p role="alert" className="mt-4 text-red-700">{error}</p>}
    </form>
    {result && <section className="mt-6 rounded-xl border bg-white p-6 shadow-sm">
      <h2 className="text-xl font-semibold">Result: <span className="capitalize">{result.decision.toLowerCase()}</span></h2>
      <p className="mt-2">Risk score: {result.final_risk_score}/100 · Confidence: {(result.confidence * 100).toFixed(0)}%</p>
      <p className="mt-2 text-gray-700">{result.reason}</p>
      <p className="mt-3 text-sm text-gray-600">
        Rule score {result.rule_score} · ML signal {(result.ml_probability * 100).toFixed(0)}%
        {result.gemini_used ? ` · Gemini score ${result.gemini_risk_score}` : ' · Gemini not used'}
      </p>
      <Link className="mt-4 inline-block text-blue-700 underline" to={`/assessments/${result.id}`}>View saved assessment</Link>
    </section>}
  </section>;
}
