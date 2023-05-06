package br.pucpr.authserver.users

import org.springframework.stereotype.Service

@Service
class UsersService(val repository: UsersRepository) {
    fun save(user: User) = repository.save(user)

    fun getById(id: Long) = repository.findById(id)

    fun findAll() = repository.findAll()
}