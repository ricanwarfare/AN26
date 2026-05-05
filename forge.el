(defvar forge-unixtime nil)
(defvar forge-greedy t)

(defun utcstamp ()
  "Insert a utc timestamp."
  (interactive)
  (insert
   (format-time-string
    (if forge-unixtime
	"[ %s ]"
      "[ %H:%M:%S %Z, %d %b %y ]")
    (current-time) t)))

(global-set-key (kbd "C-c s") 'utcstamp)

(defun forge-toggleunixtime ()
  (interactive)
  (setq forge-unixtime (not forge-unixtime)))

(defun forge-togglegreedy ()
  (interactive)
  (setq forge-greedy (not forge-greedy)))

(defun copy-line ()
  (interactive)
  (let ((line (buffer-substring-no-properties
	       (line-beginning-position)
	       (line-end-position))))
    (kill-new (string-trim-right line))
    (message line)))

(defun mouse-copy-line (e)
  (interactive "e")
  (mouse-set-point e)
  (copy-line))

(defun cmd-list-newline ()
  (interactive)
  (copy-line)
  (if forge-greedy (progn
		     (insert "\n# ")
		     (utcstamp)
		     (insert "\n\n"))
    (insert "\n")))

(defun forge-annotate ()
  (interactive)
  (insert "\n# ")
  (utcstamp)
  (insert "\n\n"))

(defvar-keymap forge-mode-map
  "<mouse-3>" #'mouse-copy-line
  "<return>" #'cmd-list-newline
  "C-c a" #'forge-annotate
  "C-c g" #'forge-togglegreedy
  "C-c C-c" #'copy-line
  "C-c p" #'forge-toggleunixtime)

(define-minor-mode forge-mode
  "Allows for easy timestamping and copying for operations."
  :lighter " FORGE"
  :keymap forge-mode-map)

(provide 'forge)
