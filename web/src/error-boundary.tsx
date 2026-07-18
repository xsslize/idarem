import { Component, type ErrorInfo, type ReactNode } from "react";

export class ErrorBoundary extends Component<{ children: ReactNode }, { error: Error | null }> {
  state = { error: null as Error | null };

  static getDerivedStateFromError(error: Error) {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("idarem render failure", error, info);
  }

  render() {
    if (!this.state.error) return this.props.children;
    return (
      <div className="fatal-error">
        <h1>idarem encountered a rendering error</h1>
        <pre>{this.state.error.message}</pre>
        <button onClick={() => window.location.reload()}>Reload</button>
      </div>
    );
  }
}
