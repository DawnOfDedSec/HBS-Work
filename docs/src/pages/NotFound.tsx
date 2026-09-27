import { Link } from 'react-router-dom';

export default function NotFound() {
  return (
    <div className="mx-auto flex min-h-[50vh] max-w-[760px] flex-col items-center justify-center px-6 py-16 text-center">
      <p className="mono-label">404</p>
      <h1 className="mt-3 text-4xl font-extrabold">
        <span className="grad-text">Page not found</span>
      </h1>
      <p className="mt-4 max-w-[480px] text-muted">
        This route does not exist. Documentation, examples and the project pages all live on their own
        routes.
      </p>
      <nav className="mt-8 flex flex-wrap justify-center gap-3">
        <Link to="/" className="btn-primary">
          Docs home
        </Link>
        <Link to="/docs" className="btn-ghost">
          Documentation
        </Link>
        <Link to="/examples" className="btn-ghost">
          Examples
        </Link>
        <a
          href="https://github.com/PotenFYR-Studios/HBS-Tool"
          target="_blank"
          rel="noopener noreferrer"
          className="btn-ghost"
        >
          GitHub repository
        </a>
      </nav>
    </div>
  );
}
