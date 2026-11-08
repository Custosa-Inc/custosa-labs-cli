package org.clinic.web

@RestController
class PatientController(private val repo: PatientRepository) {
    @PostMapping("/patients")
    fun create(@RequestBody dto: PatientDto, auth: Authentication): Patient {
        val p = Patient()
        // ruleid: write-fields-allowlisted.kotlin-spring.copy-all
        BeanUtils.copyProperties(dto, p)
        // ruleid: write-fields-allowlisted.kotlin-spring.identity-from-request
        // ruleid: write-fields-allowlisted.kotlin-spring.identity-field
        p.ownerId = dto.ownerId
        // ok: write-fields-allowlisted.kotlin-spring.identity-from-request
        // ok: write-fields-allowlisted.kotlin-spring.identity-field
        p.createdBy = auth.name
        // ok: write-fields-allowlisted.kotlin-spring.copy-all
        p.name = dto.name
        return repo.save(p)
    }

    @PostMapping("/visits")
    fun visit(@RequestBody dto: VisitDto, principal: Principal): Visit {
        // ok: write-fields-allowlisted.kotlin-spring.identity-field
        val v = Visit(note = dto.note, authorId = principal.name)
        // ruleid: write-fields-allowlisted.kotlin-spring.identity-field
        val w = Visit(note = dto.note, clinicId = dto.clinicId)
        // ok: write-fields-allowlisted.kotlin-spring.identity-field
        v.note = dto.note
        return repo.save(v)
    }
}
