export const isPublicMode = (): boolean => {
  if (typeof document !== 'undefined') {
    const body = document.body;
    return body?.dataset?.publicMode === 'true';
  }
  return true;
};

export const isBuilderEnabled = (): boolean => {
  return !isPublicMode();
};

export const getMode = (): 'public' | 'dev' => {
  return isPublicMode() ? 'public' : 'dev';
};
