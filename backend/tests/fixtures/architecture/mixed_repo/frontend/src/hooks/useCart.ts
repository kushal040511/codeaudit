import { fetchCart } from '../api/client.js'

export function useCart() {
  return fetchCart()
}
