import React from 'react';
import DashboardViewer from './DashboardViewer';
import type { SavedDashboard } from './dashboardStorage';
import sampleData from '../../assets/sample-dashboard.json';

function PublicDashboardViewer() {
  // Directly render the viewer with sample data, no AuthWrapper
  // We pass publicMode={true} to adjust navigation and banners
  return (
    <div className="public-viewer-wrapper" style={{ height: '100vh', display: 'flex', flexDirection: 'column' }}>
      <DashboardViewer dashboard={sampleData as SavedDashboard} publicMode={true} />
    </div>
  );
}

export default PublicDashboardViewer;
