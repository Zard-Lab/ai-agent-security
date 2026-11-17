// Regression fixture mirroring a REAL 9_Agent_SaaS finding: raw HTML in
// agent/user markdown is rendered with no sanitizer plugin, so it reaches the
// DOM unchecked. Expected: frontend-xss/rehype-raw-unsanitized (HIGH).
import ReactMarkdown from "react-markdown";
import rehypeRaw from "rehype-raw";
import remarkGfm from "remark-gfm";

export function MessageItem({ content }: { content: string }) {
  return (
    <ReactMarkdown remarkPlugins={[remarkGfm]} rehypePlugins={[rehypeRaw]}>
      {content}
    </ReactMarkdown>
  );
}
