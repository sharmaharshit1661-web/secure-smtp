import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import Layout from './components/Layout';
import FleetOverview from './pages/FleetOverview';
import SessionExplorer from './pages/SessionExplorer';
import LiveIngest from './pages/LiveIngest';
import RulesCompliance from './pages/RulesCompliance';

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Layout />}>
          <Route index element={<FleetOverview />} />
          <Route path="sessions" element={<SessionExplorer />} />
          <Route path="sessions/:hostId" element={<SessionExplorer />} />
          <Route path="ingest" element={<LiveIngest />} />
          <Route path="rules" element={<RulesCompliance />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
