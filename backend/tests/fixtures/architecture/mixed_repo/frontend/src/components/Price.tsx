export function Price({ value }: { value: number }) {
  return <span>{value.toFixed(2)}</span>
}
