// Well-handled errors: no finding, every component 1.0.
export async function loadUser(id) {
  try {
    const response = await fetch(`/users/${id}`);
    return await response.json();
  } catch (error) {
    throw new Error(`could not load user ${id}`, { cause: error });
  }
}

export function prefetch(url, cache) {
  fetch(url)
    .then((response) => cache.put(url, response))
    .catch((error) => cache.fail(url, error));
}
