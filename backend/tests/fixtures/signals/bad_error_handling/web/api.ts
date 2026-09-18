import axios from "axios";

export async function load(id: string): Promise<unknown> {
  const { data } = await axios.get(`/items/${id}`);
  return data;
}

export function legacy(): XMLHttpRequest {
  return new XMLHttpRequest();
}

export function query(db: { query: (sql: string) => Promise<unknown> }): void {
  db.query("select 1").then((rows) => rows);
}
