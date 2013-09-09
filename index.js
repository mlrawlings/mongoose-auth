var bcrypt = require('bcrypt-nodejs')

module.exports = function(schema, options) {
	
	schema.pre('save', function(next) {
	    var employee = this
		if (!employee.isModified(options.pass)) return next()
		else bcrypt.hash(employee[options.pass], null, null, function(err, hash) {
			if (!err) employee[options.pass] = hash
			return next(err)
		})
	})

	schema.statics.getAuthenticated = function(user, pass, fn) {
		var query = this.findOne(getUserQuery(user, options.user))
		query.exec(function(err, employee) {
			if (err) return fn(err);
			if (!employee) return fn('Invalid Credentials');
			bcrypt.compare(pass, employee[options.pass], function(err, match) {
			    if (err) return fn(err)
			    if (match) fn(null, employee)
			    else fn('Invalid Credentials')
			})
		})
	}
	
}

function getUserQuery(user, fields) {
	var fields = fields.split('|')
	  , query = {}
	if(fields.length == 1) {
		query[fields[0]] = user
	} else {
		query.$or = []
		for(var i = 0; i < fields.length; i++) {
			var subQuery = {}
			subQuery[fields[i]] = user
			query.$or.push(subQuery)
		}
	}
	return query
}