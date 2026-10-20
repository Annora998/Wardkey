package broker

// Close locks the session and clears its retained audit key.
func (h *Handler) Close() {
	if h != nil && h.session != nil {
		h.session.Close()
	}
}
