import { Component, type ReactNode } from "react";

// A page crash must never blank the whole appliance UI. This shows the error
// and a reload, keeping the surrounding navigation usable.
export class ErrorBoundary extends Component<{ children: ReactNode; where: string }, { err: Error | null }> {
  state = { err: null as Error | null };
  static getDerivedStateFromError(err: Error) { return { err }; }
  componentDidUpdate(prev: { children: ReactNode; where: string }) {
    if (prev.where !== this.props.where && this.state.err) this.setState({ err: null });
  }
  render() {
    if (this.state.err) {
      return (
        <div className="page">
          <div className="banner bad"><div>
            <b>This page hit an error.</b>
            {String(this.state.err.message || this.state.err)}. The rest of the appliance is unaffected — pick another page, or reload.
          </div></div>
          <button onClick={() => location.reload()}>Reload</button>
        </div>
      );
    }
    return this.props.children;
  }
}
