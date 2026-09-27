import { useRef, type KeyboardEvent, type ReactNode } from 'react';

export type TabItem<T extends string> = {
  value: T;
  label: string;
  icon?: ReactNode;
};

interface TabsProps<T extends string> {
  items: ReadonlyArray<TabItem<T>>;
  value: T;
  onChange: (value: T) => void;
  /** Accessible name for the tablist. */
  label: string;
  idBase: string;
  children: ReactNode;
}

/**
 * Tabs with a roving tabindex and arrow-key navigation: only the selected tab
 * is in the tab order, Left/Right/Home/End move the selection. Used by the
 * audience switcher, which is four near-identical cards in the old layout.
 *
 * Children are rendered by the caller so the panel content stays next to the
 * data it renders.
 */
export default function Tabs<T extends string>({
  items,
  value,
  onChange,
  label,
  idBase,
  children,
}: TabsProps<T>) {
  const listRef = useRef<HTMLDivElement>(null);

  function onKeyDown(event: KeyboardEvent<HTMLDivElement>) {
    const index = items.findIndex((i) => i.value === value);
    let next = index;
    if (event.key === 'ArrowRight' || event.key === 'ArrowDown') next = (index + 1) % items.length;
    else if (event.key === 'ArrowLeft' || event.key === 'ArrowUp') next = (index - 1 + items.length) % items.length;
    else if (event.key === 'Home') next = 0;
    else if (event.key === 'End') next = items.length - 1;
    else return;

    event.preventDefault();
    const target = items[next];
    onChange(target.value);
    listRef.current
      ?.querySelector<HTMLButtonElement>(`[data-tab="${CSS.escape(target.value)}"]`)
      ?.focus();
  }

  return (
    <div>
      <div
        ref={listRef}
        role="tablist"
        aria-label={label}
        onKeyDown={onKeyDown}
        className="flex flex-wrap gap-1.5 rounded-xl border border-hairline bg-wash p-1.5"
      >
        {items.map((item) => {
          const selected = item.value === value;
          return (
            <button
              key={item.value}
              type="button"
              role="tab"
              data-tab={item.value}
              id={`${idBase}-tab-${item.value}`}
              aria-selected={selected}
              aria-controls={`${idBase}-panel-${item.value}`}
              tabIndex={selected ? 0 : -1}
              onClick={() => onChange(item.value)}
              className="tab"
            >
              {item.icon}
              {item.label}
            </button>
          );
        })}
      </div>
      <div
        role="tabpanel"
        id={`${idBase}-panel-${value}`}
        aria-labelledby={`${idBase}-tab-${value}`}
        tabIndex={0}
        className="mt-4"
      >
        {children}
      </div>
    </div>
  );
}
