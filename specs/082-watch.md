# Spec: Watched Folders

## Status

Implemented.

Conformance covers the DAG definition. The scheduler's reading of folders
and the runs it starts are covered by scheduler unit tests and the queue
integration tests.

## Scope

This spec defines the DAG-level `watch` block, which starts a run for each
file that arrives in a folder. It does not define file system events,
recursive watching, or what the run does with the file.

## Goal

Workflow authors can hand a folder to a workflow: a file dropped there is
processed once, by one run, soon after it is complete, without a schedule
that polls the folder and leaves empty runs behind.

## Behavior

- `watch.path` is the folder watched and is required. A leading `~` is the
  home directory; a relative path is resolved against the scheduler's
  working directory.
- `watch.pattern` is a glob the file's name must match, as `filepath.Match`
  takes it, such as `*.pdf`. Empty, or `*`, matches every file. Files whose
  names start with `.` or `~$`, files with an in-progress extension
  (`.tmp`, `.part`, `.partial`, `.crdownload`, `.download`), folders, and
  files that are not regular never match.
- `watch.interval` is how often the folder is read, as a duration such as
  `30s`. It defaults to 10s and must be at least 1s.
- A DAG with `watch` needs no `schedule`; both may be set.
- The scheduler reads the folder every interval. A file counts as arrived
  once its size and modification time are the same on two readings in a
  row, so a file still being copied waits. Each arrival starts one run,
  queued like a webhook's, with the runtime params `WATCH_FILE`, the file's
  absolute path, and `WATCH_NAME`, its name. The run's trigger type is
  `file`.
- The scheduler remembers each file by its size and modification time, so
  a file runs once. A file replaced with other content runs again. A file
  that a reading found gone is forgotten, so when a later reading finds it
  again it runs again, changed or not. A file moved out and back between
  two readings, or while the scheduler is off, was never found gone and
  does not run again.
- Each arrival is numbered in the record, and the record is saved, before
  its run is queued. The run is named after the arrival (`file-` and a hash
  of the DAG, the record's own random name, and the arrival's number). The
  same arrival queued again, as when the scheduler stopped between queuing
  the run and recording that it did, is the run the queue already holds;
  another arrival of the file, of the same version or another, is another
  run. An arrival that could not be saved is not queued until it is.
- A record made anew, because `path` or `pattern` changed or the record was
  lost, has a name of its own, so its numbers never name an earlier run.
  When the record is lost, the files the folder holds are taken as already
  there: an arrival whose run was not yet queued then does not run, and no
  run is queued twice. A record written before arrivals were numbered
  (version 1) is read with each of its files as handled.
- `WATCH_FILE` and `WATCH_NAME` are chosen by whoever put the file in the
  folder: a `run:` step reads them with `printenv` or through
  `template.render` rather than interpolating them into its command.
- The files a folder holds when it is first watched, or when `path` or
  `pattern` change, are remembered without running: a watch takes what
  arrives, not what was there. A file that arrives while the scheduler is
  off is new when it returns.
- A suspended DAG starts no runs; its files wait and run once it resumes.
  A file whose run could not be queued is tried again at the next reading.
  A waiting file that changes waits to hold still again, and only its new
  version runs.
- A folder that cannot be read is reported once in the scheduler log, and
  read again every interval until it can be.
- The record of watched folders is kept with the scheduler's state and
  survives restarts. A record that cannot be read is tried again every
  second, and no folder is read until it is; a record that is corrupt is
  started over. A DAG the scheduler leaves out for a while, as one
  being edited is, keeps its record, so a file that arrives meanwhile runs
  once the DAG is back; the record of a DAG that is gone for good stays.

## Errors

`dagu validate` rejects a `watch` without `path`, a `pattern` that is not a
valid glob, an `interval` that is not a duration, and an `interval` under
1s. `watch.files` and other fields are rejected by the schema.

## Example

```yaml
watch:
  path: ~/Downloads/invoices
  pattern: "*.pdf"
  interval: 30s
steps:
  - id: read
    action: chat.completion
    with:
      prompt: Read the invoice and give its number, date, and total.
      files: ${WATCH_FILE}
    output_schema:
      type: object
      properties:
        number: {type: string}
        date: {type: string}
        total: {type: number}
      required: [number]
  - id: file
    depends: read
    action: file.move
    with:
      source: ${WATCH_FILE}
      destination: ~/Documents/invoices/${steps.read.outputs.number}.pdf
```
