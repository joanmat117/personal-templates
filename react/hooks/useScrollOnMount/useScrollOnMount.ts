import { useRef, useEffect } from 'react';

export function useScrollOnMount(options = {}) {
  const ref = useRef<HTMLDivElement|null>(null);
  const isFirstMount = useRef(true)
  
  useEffect(() => {
    if (ref.current && isFirstMount.current) {
      ref.current.scrollIntoView({
        behavior: 'smooth',
        block: 'start',
        ...options
      });
      isFirstMount.current = false
    }
  }, [options]);

  return ref;
}
