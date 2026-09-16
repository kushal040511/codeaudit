import { useCart } from '@/hooks/useCart'

export default function Settings() {
  return <pre>{JSON.stringify(useCart())}</pre>
}
