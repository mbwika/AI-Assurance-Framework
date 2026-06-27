import { useEffect, useState } from "react";

// Fetches a resource and tracks loading/error/data, re-running when `deps` change
// (e.g. the refresh token). Ignores results from stale requests.
export function useResource(fetcher, deps) {
  const [state, setState] = useState({ loading: true, error: null, data: null });
  useEffect(() => {
    let active = true;
    setState((prev) => ({ ...prev, loading: true, error: null }));
    fetcher()
      .then((data) => active && setState({ loading: false, error: null, data }))
      .catch((error) => active && setState({ loading: false, error: error.message, data: null }));
    return () => {
      active = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
  return state;
}
