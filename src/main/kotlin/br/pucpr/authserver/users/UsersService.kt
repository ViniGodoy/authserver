package br.pucpr.authserver.users

import br.pucpr.authserver.users.requests.UserRequest
import org.springframework.data.domain.Sort
import org.springframework.stereotype.Service

@Service
class UsersService(val repository: UsersRepository,
                   val rolesRepository: RolesRepository) {
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
}