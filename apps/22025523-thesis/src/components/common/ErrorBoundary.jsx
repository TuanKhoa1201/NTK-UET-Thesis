import {Component} from 'react';

export default class ErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = {failed: false};
  }

  static getDerivedStateFromError() {
    return {failed: true};
  }

  componentDidCatch(error, info) {
    if (import.meta.env.DEV) {
      console.error('[Scanner UI] Render exception:', error);
      console.error('[Scanner UI] Exception message:', error?.message);
      console.error('[Scanner UI] Exception stack:', error?.stack);
      console.error('[Scanner UI] Component stack:', info.componentStack);
    }
  }

  render() {
    if (this.state.failed) {
      return this.props.fallback?.(() => this.setState({failed: false})) || (
        <section className="card" role="alert">
          <h2>Không thể hiển thị khu vực phân tích</h2>
          <p>Trang điều hướng vẫn hoạt động. Vui lòng thử tải lại khu vực này.</p>
          <button className="button-secondary" onClick={() => this.setState({failed: false})}>Thử lại</button>
        </section>
      );
    }

    return this.props.children;
  }
}