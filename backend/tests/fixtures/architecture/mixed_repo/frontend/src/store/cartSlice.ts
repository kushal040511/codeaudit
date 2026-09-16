import { Price } from '@/components/Price'
import type { Cart } from '../types'

// Layer inversion: the store (lowest layer) depends on a UI component.
export const cartStore: { current: Cart; render: typeof Price } = {
  current: { items: [] },
  render: Price,
}
