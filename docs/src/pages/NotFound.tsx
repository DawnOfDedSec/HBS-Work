import { Link } from 'react-router-dom';
import { FileQuestion } from 'lucide-react';

export default function NotFound() {
  return (
    <div className="mx-auto flex min-h-[60vh] max-w-[760px] flex-col items-center justify-center px-6 py-16 text-center">
      <span className="icon-tile !h-12 !w-12">
        <FileQuestion size={20} aria-hidden="true" />
      </span>
      <p className="mono-label mt-5">Error 404</p>
      <h1 className="mt-3 text-[clamp(1.8rem,4vw,2.6rem)] font-bold">This route does not exist</h1>
      <p className="mt-4 max-w-[480px] leading-relaxed text-muted">
        Documentation, examples and the project pages all live on their own routes. The pipeline
        diagram on the home page is a reasonable place to restart.
      </p>
      <nav className="mt-8 flex flex-wrap justify-center gap-3">
        <Link to="/" className="btn-primary">
          Back to the overview
        </Link>
        <Link to="/docs" className="btn-ghost">
          Documentation
        </Link>
        <Link to="/examples" className="btn-ghost">
          Examples
        </Link>
      </nav>
    </div>
  );
}
