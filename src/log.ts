// Tracks attack results — records each scenario outcome and provides a summary

export interface AttackResult {
  scenarioId: string;
  scenarioName: string;
  category: string;
  expectedOutcome: string;
  actualOutcome: string;
  caught: boolean;
  details: string;
}

export class AttackLog {
  private results: AttackResult[] = [];

  record(result: AttackResult): void {
    this.results.push(result);
  }

  getResults(): AttackResult[] {
    return [...this.results];
  }
}
