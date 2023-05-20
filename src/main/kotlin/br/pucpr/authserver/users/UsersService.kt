package br.pucpr.authserver.users

import br.pucpr.authserver.security.Jwt
import br.pucpr.authserver.users.requests.LoginRequest
import br.pucpr.authserver.users.requests.UserRequest
import br.pucpr.authserver.users.responses.LoginResponse
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

    fun getById(id: Long) = repository.findById(id)

    fun findAll(role: String?): List<User> =
        if (role == null) repository.findAll(Sort.by("name"))
        else repository.findAllByRole(role)

    fun login(credentials: LoginRequest): LoginResponse? {
        val user = repository.findByEmail(credentials.email!!) ?: return null
        if (user.password != credentials.password) return null
        return LoginResponse(
            token = jwt.createToken(user),
            user.toResponse()
        )
    }

    fun delete(id: Long): Boolean {
        val user = repository.findByIdOrNull(id) ?: return false
        if (user.roles.any { it.name == "ADMIN" }) {
            val count = repository.findAllByRole("ADMIN").size
            if (count == 1) return false
        }
        repository.delete(user)
        return true
    }
}