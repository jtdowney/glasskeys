let pendingAbort = null;

export function setPendingAbort(abort) {
  pendingAbort = abort;
}

export function runPendingAbort() {
  const abort = pendingAbort;
  pendingAbort = null;
  if (abort) abort();
}
