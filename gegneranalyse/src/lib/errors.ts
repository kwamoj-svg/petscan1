export class AnalysisError extends Error {
  constructor(
    public userMessage: string,
    public statusCode: number = 500,
    originalError?: unknown
  ) {
    super(userMessage);
    this.name = 'AnalysisError';
    if (originalError instanceof Error) {
      this.cause = originalError;
    }
  }
}

export function errorResponse(error: unknown) {
  if (error instanceof AnalysisError) {
    return Response.json(
      { error: error.userMessage },
      { status: error.statusCode }
    );
  }
  console.error('Unerwarteter Fehler:', error);
  return Response.json(
    { error: 'Ein unerwarteter Fehler ist aufgetreten. Bitte versuche es erneut.' },
    { status: 500 }
  );
}
