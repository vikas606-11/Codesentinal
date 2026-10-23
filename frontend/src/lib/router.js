import { useEffect, useState } from "react";

// Minimal hash router: #/  #/scan  #/scans/<id>
export function useRoute() {
  const read = () => window.location.hash.replace(/^#/, "") || "/";
  const [path, setPath] = useState(read);
  useEffect(() => {
    const onChange = () => setPath(read());
    window.addEventListener("hashchange", onChange);
    return () => window.removeEventListener("hashchange", onChange);
  }, []);
  return path;
}

export function navigate(path) {
  window.location.hash = path;
}
