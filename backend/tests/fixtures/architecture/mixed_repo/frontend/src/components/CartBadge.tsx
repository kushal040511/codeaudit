import { useCart } from '../hooks/useCart'

export function CartBadge() {
  const cart = useCart()
  return <span>{cart.items.length}</span>
}
