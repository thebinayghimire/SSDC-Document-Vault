// Use the same maintained Django catalogue for server and browser messages.
export function t(message, values) {
  const translated = window.gettext ? window.gettext(message) : message;
  return values ? translated.replace(/%\((\w+)\)s/g, (_, key) => String(values[key] ?? '')) : translated;
}
