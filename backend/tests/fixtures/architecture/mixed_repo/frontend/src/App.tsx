import { lazy } from 'react'
import { CartBadge } from '@/components/CartBadge'
import logo from './logo.svg'

const Settings = lazy(() => import('./pages/Settings'))

export default function App() {
  return (
    <div>
      <img src={logo} />
      <CartBadge />
      <Settings />
    </div>
  )
}
