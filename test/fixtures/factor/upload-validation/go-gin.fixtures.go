package handler

// Made-up upload handlers. A control counts only in a canonical, fully bound shape in the handler's
// own scope; a shape that only resembles one is evidence (type-candidate, size-candidate, auth-unobserved); a
// violation fires only when the absence is visible in this file.

// Bypass (black-box): an unscanned Go upload handler with the client's name as the key. A named handler's
// route and middleware aren't visible here, so missing auth is unobserved (needs_review), not a fail.
// ruleid: upload-validation.go-gin.handler
// ruleid: upload-validation.go-gin.no-content-type-check
// ruleid: upload-validation.go-gin.no-size-limit
// ruleid: upload-validation.go-gin.auth-unobserved
// ok: upload-validation.go-gin.no-authorization
// ok: upload-validation.go-gin.scan-unchecked
func Avatar(c *gin.Context) {
	file, _ := c.FormFile("file")
	// ruleid: upload-validation.go-gin.original-name-key
	// ok: upload-validation.go-gin.scan-candidate
	c.SaveUploadedFile(file, filepath.Join("uploads", file.Filename))
}

// ok: upload-validation.go-gin.handler
// ok: upload-validation.go-gin.no-content-type-check
// ok: upload-validation.go-gin.type-candidate
// ok: upload-validation.go-gin.no-size-limit
// ok: upload-validation.go-gin.size-candidate
// ok: upload-validation.go-gin.no-authorization
// ok: upload-validation.go-gin.auth-unobserved
func Document(c *gin.Context) {
	user := c.MustGet("user")
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxUpload)
	f, _, _ := c.Request.FormFile("file")
	head := make([]byte, 512)
	f.Read(head)
	if kind := http.DetectContentType(head); !allowed[kind] {
		c.AbortWithStatus(415)
		return
	}
	// ruleid: upload-validation.go-gin.scan-candidate
	if infected, _ := clamd.ScanStream(f); infected {
		c.AbortWithStatus(422)
		return
	}
	// ok: upload-validation.go-gin.original-name-key
	store(uuid.NewString(), user)
}

// The user read only for an audit actor is no authorization; it is auth evidence, so the
// absence is unobserved: auth-unobserved, never a fail.
// ruleid: upload-validation.go-gin.handler
// ruleid: upload-validation.go-gin.auth-unobserved
// ok: upload-validation.go-gin.no-authorization
// ok: upload-validation.go-gin.no-size-limit
// ok: upload-validation.go-gin.no-content-type-check
func AuditOnly(c *gin.Context) {
	actor, _ := c.Get("user")
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxUpload)
	f, _, _ := c.Request.FormFile("file")
	head := make([]byte, 512)
	f.Read(head)
	if kind := http.DetectContentType(head); !allowed[kind] {
		c.AbortWithStatus(415)
		return
	}
	audit(actor)
	store(uuid.NewString(), f)
}

// A missing user rejected before the upload is read: authorization.
// ruleid: upload-validation.go-gin.handler
// ok: upload-validation.go-gin.no-authorization
// ok: upload-validation.go-gin.auth-unobserved
func Guarded(c *gin.Context) {
	user, ok := c.Get("user")
	if !ok {
		c.AbortWithStatus(401)
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxUpload)
	f, _, _ := c.Request.FormFile("file")
	head := make([]byte, 512)
	f.Read(head)
	if kind := http.DetectContentType(head); !allowed[kind] {
		c.AbortWithStatus(415)
		return
	}
	store(uuid.NewString(), user)
}

// More cases, with the outcome the rules give.
// MustGet of the injected DB is no authorization; a named handler: auth-unobserved, not a fail.
// ok: upload-validation.go-gin.handler
// ruleid: upload-validation.go-gin.auth-unobserved
// ok: upload-validation.go-gin.no-authorization
func G1(c *gin.Context) {
	db := c.MustGet("db").(*gorm.DB)
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxUpload)
	f, _, _ := c.Request.FormFile("file")
	head := make([]byte, 512)
	f.Read(head)
	if kind := http.DetectContentType(head); !allowed[kind] {
		c.AbortWithStatus(415)
		return
	}
	// ruleid: upload-validation.go-gin.scan-candidate
	if infected, _ := clamd.ScanStream(f); infected {
		c.AbortWithStatus(422)
		return
	}
	store(db, uuid.NewString())
}

// an ok-check on a non-user key is no authorization: auth-unobserved.
// ruleid: upload-validation.go-gin.handler
// ruleid: upload-validation.go-gin.auth-unobserved
// ok: upload-validation.go-gin.no-authorization
// ruleid: upload-validation.go-gin.no-content-type-check
func G2(c *gin.Context) {
	cfg, ok := c.Get("config")
	if !ok {
		c.AbortWithStatus(500)
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxUpload)
	f, _, _ := c.Request.FormFile("file")
	store(cfg, f)
}

// a named handler behind group middleware: unobserved, never a fail. Routes holds no upload call of its own,
// so it is no handler.
func Routes(r *gin.Engine) {
	authed := r.Group("/api", AuthRequired())
	authed.POST("/upload", G3)
}

// ruleid: upload-validation.go-gin.handler
// ruleid: upload-validation.go-gin.auth-unobserved
// ok: upload-validation.go-gin.no-authorization
// ruleid: upload-validation.go-gin.no-content-type-check
func G3(c *gin.Context) {
	userID := c.GetString("userID")
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxUpload)
	f, _, _ := c.Request.FormFile("file")
	store(userID, f)
}

// An inline handler on a gin engine created here, no middleware on it, no auth read: the absence is
// visible. The setup function itself is no handler (the upload call sits in the literal).
func SetupRouter() *gin.Engine {
	r := gin.Default()
	// ok: upload-validation.go-gin.handler
	// ruleid: upload-validation.go-gin.no-authorization
	// ok: upload-validation.go-gin.auth-unobserved
	// ruleid: upload-validation.go-gin.size-candidate
	// ok: upload-validation.go-gin.no-size-limit
	// ruleid: upload-validation.go-gin.type-candidate
	// ok: upload-validation.go-gin.no-content-type-check
	r.POST("/open", func(c *gin.Context) {
		c.Request.ParseMultipartForm(32 << 20)
		f, h, _ := c.Request.FormFile("file")
		head := make([]byte, 512)
		f.Read(head)
		kind := http.DetectContentType(head)
		if !isAllowedType(kind) {
			c.AbortWithStatus(415)
			return
		}
		// ruleid: upload-validation.go-gin.scan-candidate
		res, _ := clamav.ScanReader(f)
		if res.Status == "FOUND" {
			c.AbortWithStatus(422)
			return
		}
		store(uuid.NewString(), h)
	})
	return r
}

// A header size checked against a limit, and the scan result's Infected field: canonical.
// ok: upload-validation.go-gin.handler
// ok: upload-validation.go-gin.no-size-limit
// ok: upload-validation.go-gin.size-candidate
func Sized(c *gin.Context) {
	user := c.MustGet("claims")
	f, h, _ := c.Request.FormFile("file")
	if h.Size > MaxUploadBytes {
		c.AbortWithStatus(413)
		return
	}
	head := make([]byte, 512)
	f.Read(head)
	if kind := http.DetectContentType(head); !allowed[kind] {
		c.AbortWithStatus(415)
		return
	}
	// ruleid: upload-validation.go-gin.scan-candidate
	res, _ := clamav.ScanReader(f)
	if res.Infected {
		c.AbortWithStatus(422)
		return
	}
	store(uuid.NewString(), user)
}

// ---- More cases.
func round5() {
	r5 := gin.Default()
	r5.Use(middleware.Gatekeeper())
	// a custom-named engine middleware may authenticate: auth unobserved, never no-authorization.
	// ok: upload-validation.go-gin.no-authorization
	// ruleid: upload-validation.go-gin.auth-unobserved
	r5.POST("/g1", func(c *gin.Context) {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, MaxUpload)
		fh, _ := c.FormFile("f")
		f, _ := fh.Open()
		head := make([]byte, 512)
		f.Read(head)
		kind := http.DetectContentType(head)
		if !allowed[kind] {
			c.AbortWithStatus(415)
			return
		}
		// ruleid: upload-validation.go-gin.scan-candidate
		if infected, _ := clamd.ScanStream(f); infected {
			c.AbortWithStatus(422)
			return
		}
		c.SaveUploadedFile(fh, uuid.NewString())
	})

	r6 := gin.New()
	r6.Use(gin.Logger(), gin.Recovery())
	routes.Register(r6)
	// A call that takes the engine may install auth: auth unobserved. Its scan verdict isn't read: scan-unchecked.
	// ok: upload-validation.go-gin.no-authorization
	// ruleid: upload-validation.go-gin.scan-unchecked
	// ruleid: upload-validation.go-gin.auth-unobserved
	// ruleid: upload-validation.go-gin.handler
	r6.POST("/g2", func(c *gin.Context) {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, MaxUpload)
		fh, _ := c.FormFile("f")
		f, _ := fh.Open()
		head := make([]byte, 512)
		f.Read(head)
		kind := http.DetectContentType(head)
		if !allowed[kind] {
			c.AbortWithStatus(415)
			return
		}
		// ruleid: upload-validation.go-gin.scan-candidate
		clamd.ScanStream(f)
		c.SaveUploadedFile(fh, uuid.NewString())
	})

	r7 := gin.New()
	r7.Use(gin.Logger(), gin.Recovery())
	log.Fatal(http.ListenAndServe(":8080", r7))
	// Only known-benign middleware and the server: the absence of auth stays visible.
	// ok: upload-validation.go-gin.auth-unobserved
	// ruleid: upload-validation.go-gin.no-authorization
	// ruleid: upload-validation.go-gin.handler
	r7.POST("/g3", func(c *gin.Context) {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, MaxUpload)
		fh, _ := c.FormFile("f")
		f, _ := fh.Open()
		head := make([]byte, 512)
		f.Read(head)
		kind := http.DetectContentType(head)
		if !allowed[kind] {
			c.AbortWithStatus(415)
			return
		}
		c.SaveUploadedFile(fh, uuid.NewString())
	})
}
