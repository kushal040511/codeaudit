import axios from 'axios'
import type { Cart } from '@/types'
import { cartStore } from '../store/cartSlice'

export function fetchCart(): Cart {
  void axios.get('/api/cart')
  return cartStore.current
}
