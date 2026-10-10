import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { AgGridReact } from "ag-grid-react";
import {
  AllCommunityModule,
  ModuleRegistry,
  themeQuartz,
  colorSchemeDark,
  colorSchemeLight
} from "ag-grid-community";
import {
  Database,
  Search,
  RefreshCw,
  Download,
  ShieldCheck,
  X,
  ChevronRight,
  FileJson,
  CircleAlert,
  FlaskConical,
  SlidersHorizontal,
  ArrowUpDown,
  Check,
  Settings,
  ChevronDown,
  Filter,
  Sun,
  Moon
} from "lucide-react";
import { Toaster, toast } from "sonner";

ModuleRegistry.registerModules([AllCommunityModule]);

const API = import.meta.env.VITE_API_URL || "http://127.0.0.1:5000";

const preferred = [
  "package_name",
  "sha256",
  "is_vulnerable",
  "vt_score",
  "malware_family",
  "file_size_mib",
  "added_date",
  "is_dummy"
];

function label(key) {
  return key.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase());
}

function display(value) {
  if (value == null) return "—";
  if (Array.isArray(value)) return value.join(", ") || "[]";
  if (typeof value === "boolean") return value ? "Yes" : "No";
  if (typeof value === "object") return JSON.stringify(value, null, 2);
  return String(value);
}

function App() {
  const gridRef = useRef(null);
  const [records, setRecords] = useState([]);
  const [total, setTotal] = useState(0);
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState("all");
  const [selected, setSelected] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [activeMenu, setActiveMenu] = useState(null);
  const [showColumnFilters, setShowColumnFilters] = useState(false);
  const [density, setDensity] = useState("comfortable");
  const [columnState, setColumnState] = useState([]);
  const [selectedRowsCount, setSelectedRowsCount] = useState(0);
  const [downloadingZip, setDownloadingZip] = useState(false);
  const [darkMode, setDarkMode] = useState(true);

useEffect(() => {
  document.documentElement.classList.toggle("dark", darkMode);
  document.body.classList.toggle("dark", darkMode);
}, [darkMode]);

  const gridTheme = useMemo(() => {
    return darkMode
      ? themeQuartz.withPart(colorSchemeDark).withParams({
          backgroundColor: "#0f172a",
          foregroundColor: "#f1f5f9",
          headerBackgroundColor: "#1e293b",
          oddRowBackgroundColor: "#131c31",
          borderColor: "#334155",
          accentColor: "#3b82f6",
          fontSize: 12
        })
      : themeQuartz.withPart(colorSchemeLight).withParams({
          backgroundColor: "#ffffff",
          foregroundColor: "#334155",
          headerBackgroundColor: "#f8fafc",
          oddRowBackgroundColor: "#fbfdff",
          borderColor: "#e2e8f0",
          accentColor: "#2563eb",
          fontSize: 12
        });
  }, [darkMode]);

  const loadRecords = useCallback(async () => {
    setLoading(true);
    setError("");

    try {
      const params = new URLSearchParams({ limit: "1000" });

      if (search.trim()) params.set("search", search.trim());
      if (filter === "real") params.set("is_dummy", "false");
      if (filter === "dummy") params.set("is_dummy", "true");
      if (filter === "vulnerable") {
        params.set("is_vulnerable", "true");
      }

      const response = await fetch(`${API}/api/metadata?${params}`);

      if (!response.ok) {
        throw new Error(`API returned ${response.status}`);
      }

      const result = await response.json();
      setRecords(Array.isArray(result.data) ? result.data : []);
      setTotal(Number(result.total) || 0);
      setSelected(null);
    } catch (err) {
      setError(
        `${err.message}. Check the API endpoint and backend connection.`
      );
      setRecords([]);
      setTotal(0);
    } finally {
      setLoading(false);
    }
  }, [search, filter]);

  useEffect(() => {
    const timer = setTimeout(loadRecords, 250);
    return () => clearTimeout(timer);
  }, [loadRecords]);


  async function downloadSelectedApks() {
    const api = gridRef.current?.api;
    const rows = api?.getSelectedRows() ?? [];

    const sha256s = [
      ...new Set(
        rows
          .map((row) => row.sha256)
          .filter(
            (hash) =>
              typeof hash === "string" && hash.trim().length > 0
          )
          .map((hash) => hash.trim())
      ),
    ];

    if (sha256s.length === 0) {
      toast.error("No valid APK identifiers selected", {
        description: "Select rows containing SHA-256 values and try again.",
      });
      return;
    }

    setDownloadingZip(true);
    setActiveMenu(null);

    const toastId = toast.loading("Preparing your ZIP download", {
      description: `Processing ${sha256s.length} selected APK(s)...`,
    });

    try {
      const response = await fetch(`${API}/api/apks/download`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ sha256s }),
      });

      if (!response.ok) {
        let message = `Download failed (${response.status})`;

        try {
          const result = await response.json();
          message = result.error || message;
        } catch {
          // Keep the fallback message for non-JSON responses.
        }

        throw new Error(message);
      }

      const blob = await response.blob();

      if (blob.size === 0) {
        throw new Error("The server returned an empty ZIP file.");
      }

      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");

      link.href = url;
      link.download = "selected-apks.zip";
      document.body.appendChild(link);
      link.click();
      link.remove();

      window.setTimeout(() => URL.revokeObjectURL(url), 1000);

      toast.success("ZIP download started", {
        id: toastId,
        description: `${sha256s.length} APK(s) packaged into ${(blob.size / 1024).toFixed(1)} KB.`,
      });
    } catch (err) {
      toast.error("APK download failed", {
        id: toastId,
        description: err.message || "Unable to download selected APKs.",
        duration: 6000,
      });
    } finally {
      setDownloadingZip(false);
    }
  }

  const columns = useMemo(() => {
    const keys = [...new Set(
      records.flatMap(record => Object.keys(record))
        .filter(key => key !== "_id")
    )];

    keys.sort((a, b) => {
      const ai = preferred.indexOf(a);
      const bi = preferred.indexOf(b);
      if (ai < 0 && bi < 0) return a.localeCompare(b);
      if (ai < 0) return 1;
      if (bi < 0) return -1;
      return ai - bi;
    });

    return keys.map(key => ({
      field: key,
      headerName: label(key),
      minWidth: key === "sha256" ? 260 : 140,
      flex: key === "package_name" ? 1.5 : 1,
      sortable: true,
      filter: true,
      resizable: true,
      tooltipValueGetter: params => display(params.value),
      valueFormatter: params => {
        const value = params.value;
        if (key.endsWith("_date") && value) {
          const date = new Date(value);
          if (!Number.isNaN(date.getTime())) {
            return date.toLocaleString();
          }
        }
        return display(value);
      },
      ...(key === "is_vulnerable" ? {
        cellRenderer: params => (
          <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium ${params.value ? "bg-red-500/10 text-red-500 border border-red-500/20" : "bg-emerald-500/10 text-emerald-500 border border-emerald-500/20"}`}>
            <span className={`w-1.5 h-1.5 rounded-full ${params.value ? "bg-red-500" : "bg-emerald-500"}`} />
            {params.value ? "Vulnerable" : "Not flagged"}
          </span>
        )
      } : {}),
      ...(key === "is_dummy" ? {
        cellRenderer: params => (
          <span className={`inline-flex items-center px-2 py-0.5 rounded-md text-xs font-medium ${params.value ? "bg-violet-500/10 text-violet-400 border border-violet-500/20" : "bg-slate-500/10 text-slate-400 border border-slate-500/20"}`}>
            {params.value ? "Test data" : "Real record"}
          </span>
        )
      } : {})
    }));
  }, [records]);

  const syncColumnState = useCallback(() => {
    const api = gridRef.current?.api;
    if (!api) return;
    setColumnState(api.getColumnState());
  }, []);

  function toggleColumn(field, visible) {
    const api = gridRef.current?.api;
    if (!api) return;
    api.setColumnsVisible([field], visible);
    syncColumnState();
  }

  function moveColumn(field, direction) {
    const api = gridRef.current?.api;
    if (!api) return;

    const state = api.getColumnState();
    const index = state.findIndex(column => column.colId === field);
    const target = index + direction;

    if (index < 0 || target < 0 || target >= state.length) return;

    api.moveColumns([field], target);
    syncColumnState();
  }

  function autoSizeColumns() {
    gridRef.current?.api.autoSizeAllColumns(false);
    syncColumnState();
  }

  function resetTableLayout() {
    const api = gridRef.current?.api;
    if (!api) return;

    api.resetColumnState();
    api.setFilterModel(null);
    api.deselectAll();
    setSelectedRowsCount(0);
    setShowColumnFilters(false);
    setDensity("comfortable");
    setActiveMenu(null);
    syncColumnState();
  }

  function exportSelectedCsv() {
    const api = gridRef.current?.api;
    if (!api || api.getSelectedRows().length === 0) return;

    api.exportDataAsCsv({
      fileName: "apk-database-selected.csv",
      onlySelected: true
    });
    setActiveMenu(null);
  }

  function exportAllCsv() {
    gridRef.current?.api.exportDataAsCsv({
      fileName: "apk-database.csv"
    });
    setActiveMenu(null);
  }

  const defaultColDef = useMemo(() => ({
    sortable: true,
    filter: true,
    resizable: true,
    floatingFilter: showColumnFilters,
    minWidth: 120
  }), [showColumnFilters]);

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-slate-950 text-slate-800 dark:text-slate-100 transition-colors">

      <Toaster
        position="top-right"
        theme={darkMode ? "dark" : "light"}
        richColors
        closeButton
      />

      <header className="sticky top-0 z-20 border-b border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900">
        <div className="mx-auto flex h-16 max-w-[1800px] items-center justify-between px-4 sm:px-6 lg:px-8">
          <h1 className="text-lg font-semibold tracking-tight text-slate-900 dark:text-white">
            APK Database
          </h1>

          <div className="flex items-center gap-2">
            <button
              onClick={() => setDarkMode(!darkMode)}
              className="inline-flex h-9 w-9 items-center justify-center rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-600 dark:text-slate-300 transition hover:bg-slate-50 dark:hover:bg-slate-700"
              title="Toggle theme"
              aria-label="Toggle theme"
            >
              {darkMode ? <Sun size={16} /> : <Moon size={16} />}
            </button>

            <button
              onClick={loadRecords}
              disabled={loading}
              title="Refresh records"
              className="inline-flex h-9 items-center justify-center gap-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 px-3 text-sm font-medium text-slate-600 dark:text-slate-300 transition hover:bg-slate-50 dark:hover:bg-slate-700 disabled:opacity-50"
            >
              <RefreshCw size={15} className={loading ? "animate-spin" : ""} />
              <span className="hidden sm:inline">Refresh</span>
            </button>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-[1800px] px-4 py-5 sm:px-6 sm:py-6 lg:px-8">
        {error && (
          <div className="mb-5 flex items-start gap-3 rounded-xl border border-red-200 bg-red-50 dark:bg-red-950/40 p-4 text-sm text-red-700 dark:text-red-400">
            <CircleAlert size={18} className="mt-0.5 shrink-0" />
            <div>
              <p className="font-semibold">Unable to load records</p>
              <p className="mt-1 break-words">{error}</p>
              <button
                onClick={loadRecords}
                className="mt-2 font-semibold underline underline-offset-2"
              >
                Try again
              </button>
            </div>
          </div>
        )}

        <section className="overflow-hidden rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 shadow-sm">
          <div className="flex flex-col gap-4 border-b border-slate-200 dark:border-slate-800 p-4 sm:p-5 bg-white dark:bg-slate-900">
            <div className="flex flex-col gap-3 xl:flex-row xl:items-center xl:justify-between">
              
              <div className="relative w-full xl:max-w-md">
                <Search
                  size={17}
                  className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-slate-400"
                />
                <input
                  value={search}
                  onChange={event => setSearch(event.target.value)}
                  placeholder="Search APK records..."
                  className="h-10 w-full rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 pl-10 pr-10 text-sm text-slate-900 dark:text-slate-100 outline-none placeholder:text-slate-400 focus:border-blue-500 focus:ring-2 focus:ring-blue-100 dark:focus:ring-blue-950"
                />
                {search && (
                  <button
                    onClick={() => setSearch("")}
                    aria-label="Clear search"
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200"
                  >
                    <X size={16} />
                  </button>
                )}
              </div>

              <div className="flex flex-wrap items-center gap-2">
                
                <div className="relative">
                  <button
                    onClick={() => setActiveMenu(activeMenu === "columns" ? null : "columns")}
                    className="inline-flex h-9 items-center gap-1.5 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 px-3 text-sm font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-700 transition"
                  >
                    <Database size={15} className="text-slate-500 dark:text-slate-400" />
                    Columns
                    <ChevronDown size={14} className="text-slate-400" />
                  </button>

                  {activeMenu === "columns" && (
                    <div className="absolute left-0 mt-2 w-80 rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 shadow-xl z-30">
                      <div className="flex items-center justify-between border-b border-slate-100 dark:border-slate-800 px-3 py-3">
                        <span className="text-sm font-semibold text-slate-800 dark:text-slate-200">Manage columns</span>
                        <button
                          onClick={() => gridRef.current?.api.setColumnsVisible(
                            columnState.map(column => column.colId), true
                          )}
                          className="text-xs font-medium text-blue-600 dark:text-blue-400 hover:underline"
                        >
                          Show all
                        </button>
                      </div>
                      <div className="max-h-80 overflow-y-auto p-2">
                        {columnState.map((column, index) => (
                          <div
                            key={column.colId}
                            className="flex items-center gap-2 rounded-md px-2 py-2 hover:bg-slate-50 dark:hover:bg-slate-800"
                          >
                            <input
                              type="checkbox"
                              checked={!column.hide}
                              onChange={event => toggleColumn(column.colId, event.target.checked)}
                              className="accent-blue-600 rounded"
                            />
                            <span className="min-w-0 flex-1 truncate text-sm text-slate-700 dark:text-slate-300">
                              {label(column.colId)}
                            </span>
                            <button
                              disabled={index === 0}
                              onClick={() => moveColumn(column.colId, -1)}
                              title="Move left"
                              className="rounded p-1 text-slate-500 hover:bg-slate-200 dark:hover:bg-slate-700 disabled:opacity-30"
                            >
                              <ArrowUpDown size={13} />
                            </button>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>

                <button
                  onClick={() => setShowColumnFilters(value => !value)}
                  className={`inline-flex h-9 items-center gap-1.5 rounded-lg border px-3 text-sm font-medium transition ${showColumnFilters ? "border-blue-300 bg-blue-50 dark:bg-blue-950/50 text-blue-700 dark:text-blue-300" : "border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-700"}`}
                >
                  <Filter size={15} className={showColumnFilters ? "text-blue-600 dark:text-blue-400" : "text-slate-500 dark:text-slate-400"} />
                  Filters
                  <span className="text-xs px-1.5 py-0.5 rounded bg-slate-200/60 dark:bg-slate-700 text-slate-600 dark:text-slate-300">{showColumnFilters ? "On" : "Off"}</span>
                </button>

                <div className="relative">
                  <button
                    onClick={() => setActiveMenu(activeMenu === "view" ? null : "view")}
                    className="inline-flex h-9 items-center gap-1.5 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 px-3 text-sm font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-700 transition"
                  >
                    <Settings size={15} className="text-slate-500 dark:text-slate-400" />
                    View
                    <ChevronDown size={14} className="text-slate-400" />
                  </button>

                  {activeMenu === "view" && (
                    <div className="absolute right-0 sm:left-auto mt-2 w-60 rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 p-2 shadow-xl z-30">
                      <p className="px-2 py-1 text-xs font-semibold uppercase tracking-wide text-slate-400">
                        Row density
                      </p>
                      {[
                        ["compact", "Compact rows"],
                        ["comfortable", "Comfortable rows"]
                      ].map(([value, text]) => (
                        <button
                          key={value}
                          onClick={() => {
                            setDensity(value);
                            setActiveMenu(null);
                          }}
                          className="flex w-full items-center justify-between rounded-md px-2 py-2 text-left text-sm text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800"
                        >
                          {text}
                          {density === value && <Check size={14} className="text-blue-600 dark:text-blue-400 font-bold" />}
                        </button>
                      ))}
                      <div className="my-2 border-t border-slate-100 dark:border-slate-800" />
                      <button
                        onClick={() => {
                          autoSizeColumns();
                          setActiveMenu(null);
                        }}
                        className="w-full rounded-md px-2 py-2 text-left text-sm text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800"
                      >
                        Auto-size columns
                      </button>
                      <button
                        onClick={resetTableLayout}
                        className="w-full rounded-md px-2 py-2 text-left text-sm text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-950/50"
                      >
                        Reset layout and filters
                      </button>
                    </div>
                  )}
                </div>

                <div className="relative">
                  <button
                    onClick={() => setActiveMenu(activeMenu === "export" ? null : "export")}
                    className="inline-flex h-9 items-center gap-2 rounded-lg bg-blue-600 px-3 text-sm font-medium text-white hover:bg-blue-700 transition shadow-sm"
                  >
                    <Download size={15} />
                    Export
                    <ChevronDown size={14} className="text-blue-200" />
                  </button>

                  <button
                    onClick={downloadSelectedApks}
                    disabled={selectedRowsCount === 0 || downloadingZip}
                    title="Download selected APKs as a ZIP"
                    className="inline-flex h-9 items-center gap-2 rounded-lg border border-blue-200 dark:border-blue-800 bg-blue-50 dark:bg-blue-950/50 px-3 text-sm font-medium text-blue-700 dark:text-blue-300 hover:bg-blue-100 dark:hover:bg-blue-900/60 transition disabled:cursor-not-allowed disabled:opacity-40"
                  >
                    <Download
                      size={15}
                      className={downloadingZip ? "animate-bounce" : ""}
                    />
                    {downloadingZip ? "Downloading..." : "Download ZIP"}
                    {selectedRowsCount > 0 && (
                      <span className="rounded-md bg-blue-200/70 dark:bg-blue-900 px-1.5 py-0.5 text-xs">
                        {selectedRowsCount}
                      </span>
                    )}
                  </button>

                  {activeMenu === "export" && (
                    <div className="absolute right-0 mt-2 w-56 rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 p-2 shadow-xl z-30">
                      <button onClick={exportAllCsv} className="w-full rounded-md px-3 py-2 text-left text-sm text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800">
                        Export all loaded rows
                      </button>
                      <button
                        onClick={exportSelectedCsv}
                        disabled={selectedRowsCount === 0}
                        className="w-full rounded-md px-3 py-2 text-left text-sm text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-40"
                      >
                        Export selected ({selectedRowsCount})
                      </button>
                    </div>
                  )}
                </div>

              </div>
            </div>

            <div className="flex flex-wrap items-center justify-between gap-2 pt-2 border-t border-slate-100 dark:border-slate-800 text-xs text-slate-500 dark:text-slate-400">
              <div className="flex items-center gap-3">
                <span className="font-medium text-slate-700 dark:text-slate-300">{records.length.toLocaleString()} rows loaded</span>
                <span>•</span>
                <span>{selectedRowsCount} rows selected</span>
              </div>

              <div className="flex items-center gap-3">
                <span className="inline-flex items-center gap-1.5 text-slate-600 dark:text-slate-300">
                  <FileJson size={14} className="text-slate-400" />
                  Collection: <span className="font-semibold text-slate-700 dark:text-slate-200">apkDB.metadata</span>
                </span>
                {filter === "vulnerable" && (
                  <span className="rounded-md bg-red-50 dark:bg-red-950/50 px-2 py-0.5 font-medium text-red-700 dark:text-red-400">
                    Vulnerable only
                  </span>
                )}
                {filter === "dummy" && (
                  <span className="rounded-md bg-violet-50 dark:bg-violet-950/50 px-2 py-0.5 font-medium text-violet-700 dark:text-violet-400">
                    Test records only
                  </span>
                )}
              </div>
            </div>

          </div>

          <div className="relative">
            <div className="h-[520px] w-full">
              <AgGridReact
                ref={gridRef}
                theme={gridTheme}
                rowData={records}
                columnDefs={columns}
                defaultColDef={defaultColDef}
                rowSelection={{
                  mode: "multiRow",
                  checkboxes: true,
                  headerCheckbox: true,
                  enableClickSelection: false
                }}
                pagination
                paginationPageSize={10}
                paginationPageSizeSelector={[10, 25, 50, 100]}
                rowHeight={density === "compact" ? 32 : 46}
                headerHeight={44}
                animateRows
                getRowId={params => params.data._id}
                onGridReady={syncColumnState}
                onNewColumnsLoaded={syncColumnState}
                onColumnVisible={syncColumnState}
                onColumnMoved={syncColumnState}
                onColumnResized={syncColumnState}
                onSelectionChanged={event => {
                  setSelectedRowsCount(event.api.getSelectedRows().length);
                }}
                onRowClicked={event => {
                  if (
                    event.event?.target?.closest(".ag-selection-checkbox") ||
                    event.event?.target?.closest(".ag-checkbox-input-wrapper")
                  ) return;

                  setSelected(event.data);
                }}
              />
            </div>

            {loading && (
              <div className="absolute inset-0 z-10 flex items-center justify-center bg-white/75 dark:bg-slate-900/75 backdrop-blur-[1px]">
                <div className="flex items-center gap-3 rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-800 px-4 py-3 text-sm font-medium text-slate-600 dark:text-slate-300 shadow-sm">
                  <RefreshCw size={16} className="animate-spin text-blue-600" />
                  Loading records...
                </div>
              </div>
            )}

            {!loading && !error && records.length === 0 && (
              <div className="pointer-events-none absolute inset-x-0 top-32 z-10 flex flex-col items-center gap-2 text-center">
                <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-slate-100 dark:bg-slate-800 text-slate-500">
                  <FlaskConical size={21} />
                </div>
                <p className="text-sm font-semibold text-slate-800 dark:text-slate-200">No records found</p>
                <p className="text-xs text-slate-500">
                  Try another search or select a different filter.
                </p>
              </div>
            )}
          </div>

          <div className="flex flex-col gap-1 border-t border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900/50 px-4 py-3 text-xs text-slate-500 dark:text-slate-400 sm:flex-row sm:items-center sm:justify-between sm:px-5">
            <span>
              {loading ? "Updating records..." : `Showing ${records.length.toLocaleString()} loaded records`}
            </span>
            <span>Click a row to view its complete document</span>
          </div>
        </section>

        <footer className="mt-4 flex items-start gap-2 text-xs leading-5 text-slate-500 dark:text-slate-400">
          <ShieldCheck size={14} className="mt-0.5 shrink-0 text-slate-400" />
          Vulnerability labels reflect stored metadata and do not represent a fresh security assessment.
        </footer>
      </main>

      {selected && (
        <>
          <button
            aria-label="Close document inspector"
            className="fixed inset-0 z-30 cursor-default bg-slate-950/40 backdrop-blur-[2px]"
            onClick={() => setSelected(null)}
          />
          <aside className="fixed inset-y-0 right-0 z-40 flex w-full max-w-xl flex-col border-l border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 shadow-2xl">
            <div className="flex items-start justify-between gap-4 border-b border-slate-200 dark:border-slate-800 px-5 py-5 sm:px-6">
              <div className="min-w-0">
                <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                  <FileJson size={14} />
                  Document inspector
                </div>
                <h2 className="mt-2 break-words text-lg font-semibold text-slate-900 dark:text-white">
                  {selected.package_name || "APK details"}
                </h2>
                <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
                  Full document fields and values
                </p>
              </div>
              <button
                onClick={() => setSelected(null)}
                aria-label="Close inspector"
                className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-slate-200 dark:border-slate-700 text-slate-500 dark:text-slate-400 transition hover:bg-slate-100 dark:hover:bg-slate-800 hover:text-slate-800 dark:hover:text-slate-200"
              >
                <X size={18} />
              </button>
            </div>

            <div className="flex-1 overflow-y-auto px-5 py-2 sm:px-6">
              {Object.entries(selected)
                .filter(([key]) => key !== "_id")
                .map(([key, value]) => (
                  <section key={key} className="border-b border-slate-100 dark:border-slate-800/80 py-4 last:border-0">
                    <div className="mb-2 flex items-center justify-between gap-3">
                      <label className="text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">
                        {label(key)}
                      </label>
                      {Array.isArray(value) && (
                        <span className="rounded-md bg-slate-100 dark:bg-slate-800 px-2 py-1 text-[11px] text-slate-500 dark:text-slate-400">
                          {value.length} items
                        </span>
                      )}
                    </div>
                    {Array.isArray(value) ? (
                      value.length ? (
                        <div className="flex flex-wrap gap-2">
                          {value.map((item, index) => (
                            <span
                              key={`${key}-${index}`}
                              className="max-w-full break-all rounded-md border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/50 px-2.5 py-1.5 text-xs text-slate-700 dark:text-slate-300"
                            >
                              {typeof item === "object" ? JSON.stringify(item) : String(item)}
                            </span>
                          ))}
                        </div>
                      ) : (
                        <p className="text-sm italic text-slate-400">Empty array</p>
                      )
                    ) : (
                      <pre className="whitespace-pre-wrap break-words rounded-lg border border-slate-100 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 p-3 font-mono text-xs leading-5 text-slate-700 dark:text-slate-300">
                        {display(value)}
                      </pre>
                    )}
                  </section>
                ))}
            </div>

            <div className="border-t border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900 px-5 py-3 text-xs text-slate-500 dark:text-slate-400 sm:px-6">
              Database: <span className="font-medium text-slate-700 dark:text-slate-300">apkDB.metadata</span>
            </div>
          </aside>
        </>
      )}
    </div>
  );
}

export default App;