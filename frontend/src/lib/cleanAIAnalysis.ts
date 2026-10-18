/**
 * Groq is asked for plain text, but models can still return Markdown. Keep the
 * lookup page readable without exposing formatting characters such as `**` or
 * raw link syntax to the operator.
 */
export function cleanAIAnalysis(value: string): string {
  return value
    .replace(/\r\n?/g, '\n')
    .split('\n')
    .map((line) => {
      let cleaned = line.trim();
      cleaned = cleaned.replace(/^#{1,6}\s+/, '');
      cleaned = cleaned.replace(/\[([^\]]+)\]\([^)]*\)/g, '$1');
      cleaned = cleaned.replace(/`{1,3}/g, '');
      cleaned = cleaned.replace(/\*\*([^*\n]+)\*\*/g, '$1');
      cleaned = cleaned.replace(/__([^_\n]+)__/g, '$1');
      cleaned = cleaned.replace(/(^|\s)\*([^*\n]+)\*(?=\s|$)/g, '$1$2');
      cleaned = cleaned.replace(/(^|\s)_([^_\n]+)_(?=\s|$)/g, '$1$2');
      if (/^[-*+]\s+/.test(cleaned)) cleaned = `• ${cleaned.replace(/^[-*+]\s+/, '')}`;
      return cleaned;
    })
    .join('\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}
