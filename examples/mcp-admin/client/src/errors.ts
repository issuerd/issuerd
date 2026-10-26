export class AcceptanceError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AcceptanceError";
  }
}
