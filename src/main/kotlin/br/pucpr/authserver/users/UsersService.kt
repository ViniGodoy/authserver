package br.pucpr.authserver.users

import br.pucpr.authserver.exception.BadRequestException
import br.pucpr.authserver.security.Jwt
import br.pucpr.authserver.users.requests.LoginRequest
import br.pucpr.authserver.users.requests.UserRequest
import br.pucpr.authserver.users.responses.LoginResponse
import org.slf4j.LoggerFactory
import org.springframework.data.domain.Sort
import org.springframework.data.repository.findByIdOrNull
import org.springframework.stereotype.Service

@Service
class UsersService(
    val repository: UsersRepository,
    val rolesRepository: RolesRepository,
    val jwt: Jwt
) {
    fun save(req: UserRequest): User {
        val user = User(
            email = req.email!!,
            password = req.password!!,
            name = req.name!!
        )
        val userRole = rolesRepository.findByName("USER")
            ?: throw IllegalStateException("Role 'USER' not found!")

        user.roles.add(userRole)
        return repository.save(user)
    }

    fun getById(id: Long) = repository.findByIdOrNull(id)

    fun findAll(role: String?): List<User> =
        if (role == null) repository.findAll(Sort.by("name"))
        else repository.findAllByRole(role)

    fun login(credentials: LoginRequest): LoginResponse? {
        val user = repository.findByEmail(credentials.email!!) ?: return null
        if (user.password != credentials.password) return null
        log.info("User logged in. id={} name={}", user.id, user.name)
        return LoginResponse(
            token = jwt.createToken(user),
            user.toResponse()
        )
    }

    fun delete(id: Long): Boolean {
        val user = repository.findByIdOrNull(id) ?: return false
        if (user.roles.any { it.name == "ADMIN" }) {
            val count = repository.findAllByRole("ADMIN").size
            if (count == 1)  throw BadRequestException("Cannot delete the last system admin!")
        }
        log.warn("User deleted. id={} name={}", user.id, user.name)
        repository.delete(user)
        return true
    }

    companion object {
        val log = LoggerFactory.getLogger(UsersService::class.java)
    }
}