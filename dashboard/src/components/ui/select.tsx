import { useId, type ChangeEvent, type SelectHTMLAttributes } from "react";
import { ChevronDown } from "lucide-react";
import { cn, focusRing } from "./cn";

export type SelectOption = { value: string; label: string; disabled?: boolean };

export type SelectProps = Omit<SelectHTMLAttributes<HTMLSelectElement>, "onChange" | "value" | "size"> & {
  value: string;
  onChange: (value: string) => void;
  options: SelectOption[];
  /** Rendered as a disabled first option when the value is empty. */
  placeholder?: string;
  label?: string;
  hint?: string;
  error?: string;
  size?: "sm" | "md";
  invalid?: boolean;
};

/**
 * A native select (best mobile + screen-reader behaviour) styled with the
 * console tokens. `onChange` receives the raw string value.
 */
export function Select({
  value,
  onChange,
  options,
  placeholder,
  label,
  hint,
  error,
  size = "md",
  invalid = false,
  className,
  id,
  ...rest
}: SelectProps) {
  const generatedId = useId();
  const selectId = id ?? generatedId;
  const describedBy = error ? `${selectId}-error` : hint ? `${selectId}-hint` : undefined;
  const isInvalid = invalid || Boolean(error);

  function handleChange(event: ChangeEvent<HTMLSelectElement>) {
    onChange(event.target.value);
  }

  return (
    <div className={cn("flex flex-col gap-1", className)}>
      {label ? (
        <label htmlFor={selectId} className="text-2xs font-medium text-ink-muted">
          {label}
        </label>
      ) : null}
      <div className="relative">
        <select
          id={selectId}
          value={value}
          onChange={handleChange}
          aria-invalid={isInvalid || undefined}
          aria-describedby={describedBy}
          className={cn(
            "w-full appearance-none rounded-control border bg-surface-raised pr-8 text-ink transition-colors",
            size === "sm" ? "h-8 pl-2.5 text-xs" : "h-9 pl-3 text-sm",
            isInvalid ? "border-critical/60" : "border-control-edge hover:border-control-edge-strong",
            focusRing,
          )}
          {...rest}
        >
          {placeholder ? (
            <option value="" disabled>
              {placeholder}
            </option>
          ) : null}
          {options.map((option) => (
            <option key={option.value} value={option.value} disabled={option.disabled}>
              {option.label}
            </option>
          ))}
        </select>
        <ChevronDown
          size={14}
          aria-hidden
          className="pointer-events-none absolute right-2.5 top-1/2 -translate-y-1/2 text-ink-subtle"
        />
      </div>
      {error ? (
        <p id={`${selectId}-error`} className="text-2xs text-critical">
          {error}
        </p>
      ) : hint ? (
        <p id={`${selectId}-hint`} className="text-2xs text-ink-subtle">
          {hint}
        </p>
      ) : null}
    </div>
  );
}
