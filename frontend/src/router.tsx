import { createBrowserRouter } from 'react-router'
import { AppLayout } from '@/components/layout/AppLayout'
import { HomePage } from '@/pages/HomePage'
import { NotFoundPage } from '@/pages/NotFoundPage'
import { ScanDetailPage } from '@/pages/ScanDetailPage'
import { UploadPage } from '@/pages/UploadPage'

export const router = createBrowserRouter([
  {
    path: '/',
    Component: AppLayout,
    children: [
      { index: true, Component: HomePage },
      { path: 'upload', Component: UploadPage },
      { path: 'scans/:scanId', Component: ScanDetailPage },
      { path: '*', Component: NotFoundPage },
    ],
  },
])
