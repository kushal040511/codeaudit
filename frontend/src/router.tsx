import { createBrowserRouter } from 'react-router'
import { AppLayout } from '@/components/layout/AppLayout'
import { HomePage } from '@/pages/HomePage'
import { NotFoundPage } from '@/pages/NotFoundPage'
import { ScanDetailPage } from '@/pages/ScanDetailPage'
import { SettingsPage } from '@/pages/SettingsPage'
import { SiteAnalysisPage } from '@/pages/SiteAnalysisPage'
import { SiteAnalyzerPage } from '@/pages/SiteAnalyzerPage'
import { UploadPage } from '@/pages/UploadPage'

export const router = createBrowserRouter([
  {
    path: '/',
    Component: AppLayout,
    children: [
      { index: true, Component: HomePage },
      { path: 'upload', Component: UploadPage },
      { path: 'scans/:scanId', Component: ScanDetailPage },
      { path: 'sites', Component: SiteAnalyzerPage },
      { path: 'sites/:analysisId', Component: SiteAnalysisPage },
      { path: 'settings', Component: SettingsPage },
      { path: '*', Component: NotFoundPage },
    ],
  },
])
