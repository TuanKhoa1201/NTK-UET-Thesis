import {HashRouter, Navigate, Route, Routes} from 'react-router-dom';
import './App.css';
import './styles/polish.css';
import './styles/typography.css';
import './styles/revision.css';
import './styles/analysis-revision.css';
import './styles/targeted-fixes.css';
import './styles/scene3d.css';
import './styles/scanner-resilience.css';
import './styles/ntk-final.css';
import './styles/production-readiness.css';
import AppShell from './components/layout/AppShell';
import ErrorBoundary from './components/common/ErrorBoundary';
import Overview from './pages/Overview';
import Scanner from './pages/Scanner';
import DatasetExplorer from './pages/DatasetExplorer';
import {Evaluation, Training} from './pages/ResearchPages';
import ArchitecturePage from './pages/Architecture';
import ScoringPage from './pages/Scoring';
import {FindingDetail, Results} from './pages/Results';
import {About, Reports, Review} from './pages/UtilityPages';
import StatusPage from './pages/StatusPage';
import TraceReplay from './pages/TraceReplay';
import History from './pages/HistoryPage';

function ScannerRoute() {
  return (
    <ErrorBoundary fallback={(retry) => (
      <section className="card" role="alert">
        <h2>Không thể mở khu vực phân tích</h2>
        <p>Thanh điều hướng vẫn hoạt động. Vui lòng thử tải lại trang phân tích.</p>
        <button className="button-secondary" onClick={retry}>Thử lại</button>
      </section>
    )}>
      <Scanner />
    </ErrorBoundary>
  );
}

function App() {
  return (
    <HashRouter>
      <Routes>
        <Route element={<AppShell />}>
          <Route path="/" element={<Overview />} />
          <Route path="/scanner" element={<ScannerRoute />} />
          <Route path="/history" element={<History />} />
          <Route path="/replay" element={<TraceReplay />} />
          <Route path="/results" element={<Results />} />
          <Route path="/finding/:id" element={<FindingDetail />} />
          <Route path="/findings" element={<Results />} />
          <Route path="/review" element={<Review />} />
          <Route path="/reports" element={<Reports />} />
          <Route path="/architecture" element={<ArchitecturePage />} />
          <Route path="/dataset" element={<DatasetExplorer />} />
          <Route path="/training" element={<Training />} />
          <Route path="/scoring" element={<ScoringPage />} />
          <Route path="/evaluation" element={<Evaluation />} />
          <Route path="/status" element={<StatusPage />} />
          <Route path="/about" element={<About />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </HashRouter>
  );
}

export default App;